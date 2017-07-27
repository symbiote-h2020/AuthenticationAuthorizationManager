package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.SignedObject;
import java.security.cert.CertificateException;

/**
 * Spring service used to provide token related functionality of the AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Service
public class GetTokenService {
    private static Log log = LogFactory.getLog(GetTokenService.class);
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

    public Token login(SignedObject user) throws CertificateException, WrongCredentialsException, IOException, ClassNotFoundException, MissingArgumentsException, JWTCreationException {

        // validate request
        String userCredentials = user.getObject().toString();
        if (userCredentials.split("@").length != 2 || userCredentials.split("@")[0].isEmpty() || userCredentials.split("@")[1].isEmpty()) {
            throw new MissingArgumentsException();
        }
        // try to find user
        User userInDB = userRepository.findOne(user.getObject().toString().split("@")[0]);

        // verify user credentials
        if (userInDB == null || userInDB.getClientCertificates().get(userCredentials.split("@")[1]) == null || !CryptoHelper.verifySignedObject(user, userInDB.getClientCertificates().get(userCredentials.split("@")[1]).getX509().getPublicKey())) {
            throw new WrongCredentialsException();
        }

        return this.getHomeToken(userInDB, user.getObject().toString().split("@")[1]);

    }
    public Token login() throws JWTCreationException {
        return this.getGuestToken();
    }
}
