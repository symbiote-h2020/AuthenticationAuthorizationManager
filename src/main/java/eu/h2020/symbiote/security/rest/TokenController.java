package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.commons.Constants;
import eu.h2020.symbiote.security.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.security.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.security.commons.json.RequestToken;
import eu.h2020.symbiote.security.services.TokenService;
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


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to token objects in Cloud
 * AAM component.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see TokenService
 */
@RestController
public class TokenController {

    private static Log log = LogFactory.getLog(TokenController.class);

    private final TokenService tokenService;

    @Autowired
    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    //L1 Diagrams - request_foreign_token()
    @RequestMapping(value = "/request_foreign_token", method = RequestMethod.POST)
    public ResponseEntity<?> requestForeignToken(@RequestHeader(Constants.TOKEN_HEADER_NAME) String token) throws
        JWTCreationException {

        /*
        Token(s) Validation through challenge-response (client-side)
        Validate Token(s)
        Check-Revocation Procedures (client)
        Attribute Mapping Function
        */

        RequestToken foreignToken = tokenService.exchangeForForeignToken(token);
        HttpHeaders headers = new HttpHeaders();
        headers.add(Constants.TOKEN_HEADER_NAME, foreignToken.getToken());

        /* Finally issues and return foreign_token */
        return new ResponseEntity<>(headers, HttpStatus.OK);
    }

    // L1 Diagrams - check_token_revocation()
    @RequestMapping(value = "/check_home_token_revocation", method = RequestMethod.POST)
    public ResponseEntity<?> checkHomeTokenRevocation(@RequestHeader(Constants.TOKEN_HEADER_NAME) String token) {

        return new ResponseEntity<CheckTokenRevocationResponse>(tokenService.checkHomeTokenRevocation(new
            RequestToken(token)), HttpStatus.OK);
    }
}
