package eu.h2020.symbiote.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import eu.h2020.symbiote.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.model.UserModel;
import eu.h2020.symbiote.repositories.UserRepository;

/**
 * Spring service used to provide login related functionalities of CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Service
public class LoginService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TokenService tokenService;

    public RequestToken login(LoginRequest user) throws MissingArgumentsException,WrongCredentialsException {

        // FIXME: create a default user for platform AAM in database
        userRepository.save(new UserModel("aam_username","aam_password"));

        if(user.getUsername() != null || user.getPassword() != null) {
            if(userRepository.exists(user.getUsername())){
                UserModel userInDB = userRepository.findOne(user.getUsername());
                if(user.getUsername().equals(userInDB.getUsername()) && user.getPassword().equals(userInDB.getPassword())){
                    return tokenService.getDefaultHomeToken();
                }
            }
            throw new WrongCredentialsException();
        }
        throw new MissingArgumentsException();

    }
}
