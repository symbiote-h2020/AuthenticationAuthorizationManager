package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
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
    private final TokenIssuer tokenIssuer;
    private UserRepository userRepository;


    @Autowired
    public GetTokenService(TokenIssuer tokenIssuer, UserRepository userRepository) {
        this.tokenIssuer = tokenIssuer;
        this.userRepository = userRepository;

    }

    public Token getForeignToken(String remoteHomeToken) throws JWTCreationException {
        return tokenIssuer.getForeignToken(remoteHomeToken);
    }

    public Token getGuestToken() throws JWTCreationException {
        return tokenIssuer.getGuestToken();
    }

    public Token getHomeToken(String loginRequest) throws MalformedJWTException, MissingArgumentsException, JWTCreationException, WrongCredentialsException, CertificateException, ValidationException {
        // validate request
        JWTClaims claims = JWTEngine.getClaimsFromToken(loginRequest);

        if (claims.getIss() == null || claims.getSub() == null || claims.getIss().isEmpty() || claims.getSub().isEmpty()) {
            throw new MissingArgumentsException();
        }
        // try to find user
        User userInDB = userRepository.findOne(claims.getIss());

        // verify user credentials
        if (userInDB == null
                || userInDB.getClientCertificates().get(claims.getSub()) == null
                || JWTEngine.validateTokenString(loginRequest, userInDB.getClientCertificates().get(claims.getSub()).getX509().getPublicKey()) != ValidationStatus.VALID) {
            throw new WrongCredentialsException();
        }
        return tokenIssuer.getHomeToken(userInDB, claims.getSub());
    }
}
