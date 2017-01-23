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
import eu.h2020.symbiote.services.TestService;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services binded to test operations in
 * {@link eu.h2020.symbiote.services.TestService} (FOR DEBUG/TEST PURPOSES ONLY).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@RestController
public class TestController {

	@Autowired
    private TestService testService;

    @RequestMapping(value = "/testLogin", method = RequestMethod.POST)
    public ResponseEntity<?> login(@RequestBody LoginRequest user) {

        try {
        	testService.testLogin(user);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (CustomAAMException e) {
            return new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal()), e.getStatusCode());
        }
    }
    
    @RequestMapping(value = "/testLoginMonitoring", method = RequestMethod.POST)
    public ResponseEntity<?> loginMonitoring(@RequestBody LoginRequest user) {

        try {
        	testService.testLoginMonitoring(user);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (CustomAAMException e) {
            return new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal()), e.getStatusCode());
        }
    }
    
    @RequestMapping(value = "/testCTR", method = RequestMethod.POST)
    public ResponseEntity<?> testCTR(@RequestBody RequestToken token) {

        try {
        	testService.testCTR(token);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (CustomAAMException e) {
            return new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal()), e.getStatusCode());
        }
    }
}
