package eu.h2020.symbiote.controllers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.services.TokenService;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to token objects in Cloud
 * AAM component.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see eu.h2020.symbiote.services.TokenService
 */
@RestController
public class TokenController {

	private static Log log = LogFactory.getLog(TokenController.class);
	
    @Autowired
    private TokenService tokenService;

    //L1 Diagrams - request_foreign_token()
    @RequestMapping(value = "/request_foreign_token", method = RequestMethod.POST)
    public ResponseEntity<?> requestForeignToken(@RequestHeader(Constants.TOKEN_HEADER_NAME) String token) throws JWTCreationException {

        /*
        Token(s) Validation through challenge-response (client-side)
        Validate Token(s)
        Check-Revocation Procedures (client)
        Attribute Mapping Function
        */

        // TODO: some token repository operations (make a service in TokenService class for this purpose)
        // Save token in MongoDB
        tokenService.saveToken(new RequestToken(token));
        
    	RequestToken foreignToken = tokenService.getDefaultForeignToken();
		HttpHeaders headers = new HttpHeaders();
		headers.add(Constants.TOKEN_HEADER_NAME, foreignToken.getToken());
		
        /* Finally issues and return foreign_token */
        return new ResponseEntity<>(headers,HttpStatus.OK);
    }

    // L1 Diagrams - check_token_revocation()
    @RequestMapping(value = "/check_home_token_revocation",  method = RequestMethod.POST)
    public ResponseEntity<?> checkHomeTokenRevocation(@RequestHeader(Constants.TOKEN_HEADER_NAME) String token) {

        return new ResponseEntity<CheckTokenRevocationResponse>(tokenService.checkHomeTokenRevocation(new RequestToken(token)),HttpStatus.OK);
    }
}
