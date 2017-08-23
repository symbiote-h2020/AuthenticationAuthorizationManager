package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateException;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

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
    private final TokenIssuer tokenIssuer;
    private final ComponentCertificatesRepository componentCertificateRepository;
    private UserRepository userRepository;
    private ValidationHelper validationHelper;
    private Log log = LogFactory.getLog(GetTokenService.class);
    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;

    @Autowired
    public GetTokenService(TokenIssuer tokenIssuer, UserRepository userRepository, ValidationHelper validationHelper, ComponentCertificatesRepository componentCertificateRepository) {
        this.tokenIssuer = tokenIssuer;
        this.userRepository = userRepository;
        this.validationHelper = validationHelper;
        this.componentCertificateRepository = componentCertificateRepository;
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
        if (sub.split(illegalSign).length == 2) {
            String componentOrClientId = sub.split(illegalSign)[0];
            String platformId = sub.split(illegalSign)[1];

            // verify user credentials
            if (claims.getIss().equals(AAMOwnerUsername)) {
                //authenticating
                if (JWTEngine.validateTokenString(loginRequest, componentCertificateRepository.findOne(componentOrClientId).getCertificate().getX509().getPublicKey()) != ValidationStatus.VALID)
                    throw new WrongCredentialsException();

                User user = new User();
                user.setRole(UserRole.NULL);
                user.setUsername(AAMOwnerUsername);
                return tokenIssuer.getHomeToken(user, sub, componentCertificateRepository.findOne(componentOrClientId).getCertificate().getX509().getPublicKey());
            }
            // platform owner use case
            if (userInDB == null
                    || userInDB.getOwnedPlatforms().get(platformId) == null
                    || JWTEngine.validateTokenString(loginRequest, userInDB.getOwnedPlatforms().get(platformId).getComponentCertificates().get(componentOrClientId).getX509().getPublicKey()) != ValidationStatus.VALID) {
                throw new WrongCredentialsException();
            }
            return tokenIssuer.getHomeToken(userInDB, claims.getSub(), userInDB.getOwnedPlatforms().get(platformId).getComponentCertificates().get(componentOrClientId).getX509().getPublicKey());
        }
        // ordinary user/po client
        if (userInDB == null
                || userInDB.getClientCertificates().get(claims.getSub()) == null
                || JWTEngine.validateTokenString(loginRequest, userInDB.getClientCertificates().get(claims.getSub()).getX509().getPublicKey()) != ValidationStatus.VALID) {
            throw new WrongCredentialsException();
        }
        return tokenIssuer.getHomeToken(userInDB, claims.getSub(), userInDB.getClientCertificates().get(claims.getSub()).getX509().getPublicKey());
    }
}
