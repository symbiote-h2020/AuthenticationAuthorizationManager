package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateException;

/**
 * Spring service used to provide token related functionality of the AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class GetTokenService {
    private static Log log = LogFactory.getLog(GetTokenService.class);

    private final TokenIssuer tokenIssuer;
    private final ComponentCertificatesRepository componentCertificateRepository;
    private final UserRepository userRepository;
    private final ValidationHelper validationHelper;
    private final String deploymentId;

    @Autowired
    public GetTokenService(TokenIssuer tokenIssuer, UserRepository userRepository, ValidationHelper validationHelper, ComponentCertificatesRepository componentCertificateRepository, PlatformRepository platformRepository, CertificationAuthorityHelper certificationAuthorityHelper) {
        this.tokenIssuer = tokenIssuer;
        this.userRepository = userRepository;
        this.validationHelper = validationHelper;
        this.componentCertificateRepository = componentCertificateRepository;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
    }

    public Token getForeignToken(Token receivedRemoteHomeToken, String clientCertificate, String aamCertificate) throws
            JWTCreationException,
            ValidationException {
        ValidationStatus validationStatus = validationHelper.validate(receivedRemoteHomeToken.toString(), clientCertificate, aamCertificate, "");
        if (validationStatus != ValidationStatus.VALID) {
            log.error("Validation error occurred: " + validationStatus.name());
            throw new ValidationException("Validation error occurred");
        }
        return tokenIssuer.getForeignToken(receivedRemoteHomeToken);
    }

    public Token getGuestToken() throws JWTCreationException {
        return tokenIssuer.getGuestToken();
    }

    public Token getHomeToken(String loginRequest) throws
            MalformedJWTException,
            InvalidArgumentsException,
            JWTCreationException,
            WrongCredentialsException,
            CertificateException,
            ValidationException {
        // validate request
        JWTClaims claims = JWTEngine.getClaimsFromToken(loginRequest);

        if (claims.getIss() == null || claims.getSub() == null || claims.getIss().isEmpty() || claims.getSub().isEmpty()) {
            throw new InvalidArgumentsException();
        }
        // try to find user
        String sub = claims.getSub();
        User userInDB = userRepository.findOne(claims.getIss());

        // component use case
        if (userInDB == null) {
            //authenticating
            if (!claims.getIss().equals(deploymentId) // ISS is platform id
                    || !componentCertificateRepository.exists(sub) //SUB is a componentId
                    || JWTEngine.validateTokenString(loginRequest, componentCertificateRepository.findOne(sub).getCertificate().getX509().getPublicKey()) != ValidationStatus.VALID)
                throw new WrongCredentialsException();

            User user = new User();
            user.setRole(UserRole.NULL);
            user.setUsername(""); // component case (We don't include AAMOwner/PO anymore!)
            return tokenIssuer.getHomeToken(user, sub, componentCertificateRepository.findOne(sub).getCertificate().getX509().getPublicKey());
        }
        // ordinary user/po client authentication
        if (userInDB == null
                || userInDB.getClientCertificates().get(sub) == null
                || JWTEngine.validateTokenString(loginRequest, userInDB.getClientCertificates().get(sub).getX509().getPublicKey()) != ValidationStatus.VALID) {
            throw new WrongCredentialsException();
        }
        return tokenIssuer.getHomeToken(userInDB, sub, userInDB.getClientCertificates().get(sub).getX509().getPublicKey());
    }
}
