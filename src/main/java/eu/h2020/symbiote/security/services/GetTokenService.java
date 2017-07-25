package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
    private PasswordEncoder passwordEncoder;

    @Autowired
    public GetTokenService(ValidationHelper validationHelper, TokenIssuer tokenIssuer, UserRepository userRepository,
                           PasswordEncoder passwordEncoder) {
        this.validationHelper = validationHelper;
        this.tokenIssuer = tokenIssuer;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Token createFederatedHomeTokenForForeignToken(String foreignToken) throws JWTCreationException {
        return tokenIssuer.getForeignToken(foreignToken);
    }

    /**
     * @param user which the token belongs to
     * @return Generates home token for given user
     * @throws JWTCreationException
     */
    public Token getHomeToken(User user) throws JWTCreationException {
        return tokenIssuer.getHomeToken(user);
    }

    public ValidationStatus validate(String tokenString, String certificateString) {
        return validationHelper.validate(tokenString, certificateString);
    }

    public Token login(Credentials user) throws MissingArgumentsException, WrongCredentialsException,
            JWTCreationException {
        // validate request
        if (user.getUsername().isEmpty() || user.getPassword().isEmpty()) throw new MissingArgumentsException();

        // try to find user
        User userInDB = userRepository.findOne(user.getUsername());

        // verify user credentials
        if (userInDB == null || !passwordEncoder.matches(user.getPassword(), userInDB.getPasswordEncrypted()))
            throw new WrongCredentialsException();

        return this.getHomeToken(userInDB);
    }

}
