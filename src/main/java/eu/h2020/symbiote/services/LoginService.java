package eu.h2020.symbiote.services;

import eu.h2020.symbiote.commons.Application;
import eu.h2020.symbiote.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.repositories.ApplicationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Spring service used to provide login related functionality of CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Service
public class LoginService {

    private final ApplicationRepository applicationRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public LoginService(ApplicationRepository applicationRepository,
                        TokenService tokenService, PasswordEncoder passwordEncoder) {
        this.applicationRepository = applicationRepository;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
    }

    public RequestToken login(LoginRequest user) throws MissingArgumentsException, WrongCredentialsException,
            JWTCreationException {

        if (user.getUsername() != null || user.getPassword() != null) {
            if (applicationRepository.exists(user.getUsername())) {
                Application applicationInDB = applicationRepository.findOne(user.getUsername());
                if (user.getUsername().equals(applicationInDB.getUsername())
                        && passwordEncoder.matches(user.getPassword(), applicationInDB.getPasswordEncrypted())) {
                    return tokenService.getDefaultHomeToken();
                }
            }
            throw new WrongCredentialsException();
        }
        throw new MissingArgumentsException();

    }
}
