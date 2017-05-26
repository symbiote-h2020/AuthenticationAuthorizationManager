package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.TokenManager;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.exceptions.aam.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.aam.MissingArgumentsException;
import eu.h2020.symbiote.security.exceptions.aam.WrongCredentialsException;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.repositories.RevokedTokensRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.token.Token;
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
public class TokenService {
    private static Log log = LogFactory.getLog(TokenService.class);
    private final TokenManager tokenManager;
    private RevokedTokensRepository revokedTokensRepository;
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    @Autowired
    public TokenService(TokenManager tokenManager, RevokedTokensRepository revokedTokensRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.tokenManager = tokenManager;
        this.revokedTokensRepository = revokedTokensRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Token createFederatedHomeTokenForForeignToken(String foreignToken) throws JWTCreationException {
        return tokenManager.createForeignToken(foreignToken);
    }

    /**
     * @param user which the token belongs to
     * @return Generates home token for given user
     * @throws JWTCreationException
     */
    public Token getHomeToken(User user) throws JWTCreationException {
        return tokenManager.createHomeToken(user);
    }

    public CheckRevocationResponse checkHomeTokenRevocation(String tokenString) {
        return tokenManager.checkHomeTokenRevocation(tokenString);
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
