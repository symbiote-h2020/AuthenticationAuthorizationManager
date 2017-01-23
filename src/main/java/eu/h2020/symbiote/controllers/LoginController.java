package eu.h2020.symbiote.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import eu.h2020.symbiote.commons.CustomAAMException;
import eu.h2020.symbiote.commons.json.ErrorResponseContainer;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.services.LoginService;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web service associated to user/app login service in
 * Cloud AAM component.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see eu.h2020.symbiote.services.LoginService
 */
@RestController
public class LoginController {

    @Autowired
    private LoginService loginService;

    //L1 Diagrams - login()
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity<?> login(@RequestBody LoginRequest user) {

        try {
            return new ResponseEntity<RequestToken>(loginService.login(user),HttpStatus.OK);
        } catch (CustomAAMException e) {
            return new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal()), e.getStatusCode());
        }
    }
}

