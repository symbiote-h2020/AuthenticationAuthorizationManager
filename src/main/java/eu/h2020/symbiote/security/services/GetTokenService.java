package eu.h2020.symbiote.security.services;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.HashSet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;

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
    public GetTokenService(TokenIssuer tokenIssuer,
                           UserRepository userRepository,
                           ValidationHelper validationHelper,
                           ComponentCertificatesRepository componentCertificateRepository,
                           CertificationAuthorityHelper certificationAuthorityHelper) {
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
            throw new ValidationException(ValidationException.VALIDATION_ERROR_OCCURRED);
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
        User userInDB = userRepository.findById(claims.getIss()).orElseGet(() -> null);

        User userForToken;
        PublicKey keyForToken;

        // authenticating
        if (claims.getIss().equals(deploymentId)) { // in component use case ISS is platform id
            if (!componentCertificateRepository.existsById(sub) //SUB is a componentId
                    || ValidationStatus.VALID != JWTEngine.validateTokenString(loginRequest, componentCertificateRepository.findById(sub).get().getCertificate().getX509().getPublicKey()))
                throw new WrongCredentialsException();
        } else { // ordinary user/po client
            if (userInDB == null
                    || !userInDB.getClientCertificates().containsKey(sub)
                    || ValidationStatus.VALID != JWTEngine.validateTokenString(loginRequest, userInDB.getClientCertificates().get(sub).getX509().getPublicKey()))
                throw new WrongCredentialsException();
            if (userInDB.getStatus() != AccountStatus.ACTIVE)
                throw new WrongCredentialsException(WrongCredentialsException.USER_NOT_ACTIVE, HttpStatus.FORBIDDEN);
        }

        // preparing user and key for token
        if (claims.getIss().equals(deploymentId)) { // component use case ISS is platform id
            // component case (We don't include AAMOwner/PO anymore!)
            userForToken = new User("", "", "", new HashMap<>(), UserRole.NULL, AccountStatus.ACTIVE, new HashMap<>(), new HashSet<>(), true, false);
            keyForToken = componentCertificateRepository.findById(sub).get().getCertificate().getX509().getPublicKey();
        } else {
            // ordinary user/po client
            userForToken = userInDB;
            keyForToken = userInDB.getClientCertificates().get(sub).getX509().getPublicKey();
        }
        return tokenIssuer.getHomeToken(userForToken, sub, keyForToken);
    }
}
