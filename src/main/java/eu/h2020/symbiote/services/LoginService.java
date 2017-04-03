package eu.h2020.symbiote.services;

import eu.h2020.symbiote.commons.Application;
import eu.h2020.symbiote.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.repositories.ApplicationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Spring service used to provide login related functionalities of CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Service
public class LoginService {

    @Autowired
    private ApplicationRepository applicationRepository;
    @Autowired
    private TokenService tokenService;

    public RequestToken login(LoginRequest user) throws MissingArgumentsException, WrongCredentialsException,
            JWTCreationException {

        if (user.getUsername() != null || user.getPassword() != null) {
            if (applicationRepository.exists(user.getUsername())) {
                Application applicationInDB = applicationRepository.findOne(user.getUsername());
                if (user.getUsername().equals(applicationInDB.getUsername()) && user.getPassword().equals(applicationInDB
                        .getPassword())) {
                    return tokenService.getDefaultHomeToken();
                }
            }
            throw new WrongCredentialsException();
        }
        throw new MissingArgumentsException();

    }
}
