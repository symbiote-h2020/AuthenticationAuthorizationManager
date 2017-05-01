package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.json.Credentials;
import eu.h2020.symbiote.security.commons.json.RequestToken;
import eu.h2020.symbiote.security.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Spring service used to provide login related functionality of CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class LoginService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public LoginService(UserRepository userRepository,
                        TokenService tokenService, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
    }

    public RequestToken login(Credentials user) throws MissingArgumentsException, WrongCredentialsException,
            JWTCreationException {
        // validate request
        if (user.getUsername().isEmpty() || user.getPassword().isEmpty()) throw new MissingArgumentsException();

        // try to find user
        User userInDB = userRepository.findOne(user.getUsername());

        // verify user credentials
        if (userInDB == null || !passwordEncoder.matches(user.getPassword(), userInDB.getPasswordEncrypted()))
            throw new WrongCredentialsException();

        // TODO tie token issuing request with resolved user role
        return tokenService.getHomeToken();
    }
}
