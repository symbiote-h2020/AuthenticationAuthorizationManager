package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.commons.Constants;
import eu.h2020.symbiote.security.commons.CustomAAMException;
import eu.h2020.symbiote.security.commons.payloads.Credentials;
import eu.h2020.symbiote.security.commons.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.commons.payloads.RequestToken;
import eu.h2020.symbiote.security.services.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web service associated to user/app login service in
 * Cloud AAM component.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see LoginService
 */
@RestController
public class LoginController {

    private final LoginService loginService;

    @Autowired
    public LoginController(LoginService loginService) {
        this.loginService = loginService;
    }

    //L1 Diagrams - login()
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity<?> login(@RequestBody Credentials user) {

        try {
            RequestToken token = loginService.login(user);
            HttpHeaders headers = new HttpHeaders();
            headers.add(Constants.TOKEN_HEADER_NAME, token.getToken());
            return new ResponseEntity<>(headers, HttpStatus.OK);
        } catch (CustomAAMException e) {
            return new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e
                .getStatusCode().ordinal()), e.getStatusCode());
        }
    }
}

