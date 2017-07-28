package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateException;

/**
 * Spring service used to provide token related functionality of the AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Service
public class GetTokenService {
    private final ValidationHelper validationHelper;
    private final TokenIssuer tokenIssuer;
    private UserRepository userRepository;


    @Autowired
    public GetTokenService(ValidationHelper validationHelper, TokenIssuer tokenIssuer, UserRepository userRepository) {
        this.validationHelper = validationHelper;
        this.tokenIssuer = tokenIssuer;
        this.userRepository = userRepository;

    }

    public Token createForeignHomeTokenForForeignToken(String homeToken) throws JWTCreationException {
        return tokenIssuer.getForeignToken(homeToken);
    }

    /**
     * @param user which the token belongs to
     * @return Generates home token for given user
     * @throws JWTCreationException
     */
    public Token getHomeToken(User user, String clientID) throws JWTCreationException {
        return tokenIssuer.getHomeToken(user, clientID);
    }

    private Token getGuestToken() throws JWTCreationException {
        return tokenIssuer.getGuestToken();
    }

    public ValidationStatus validate(String tokenString, String certificateString) {
        return validationHelper.validate(tokenString, certificateString);
    }

    public Token login(String loginRequest) throws MalformedJWTException, MissingArgumentsException, JWTCreationException, WrongCredentialsException, CertificateException, ValidationException {

        // validate request
        JWTClaims claims = JWTEngine.getClaimsFromToken(loginRequest);

        if (claims.getIss() == null || claims.getSub() == null || claims.getIss().isEmpty() || claims.getSub().isEmpty()) {
            throw new MissingArgumentsException();
        }
        // try to find user
        User userInDB = userRepository.findOne(claims.getIss());

        // verify user credentials
        if (userInDB == null || userInDB.getClientCertificates().get(claims.getSub()) == null || JWTEngine.validateTokenString(loginRequest, userInDB.getClientCertificates().get(claims.getSub()).getX509().getPublicKey()) != ValidationStatus.VALID) {
            throw new WrongCredentialsException();
        }

        return this.getHomeToken(userInDB, claims.getSub());

    }
    public Token login() throws JWTCreationException {
        return this.getGuestToken();
    }
}
