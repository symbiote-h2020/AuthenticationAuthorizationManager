package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.aam.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.aam.TokenValidationException;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.services.TokenService;
import eu.h2020.symbiote.security.token.Token;
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

    private final TokenService tokenService;
    private Log log = LogFactory.getLog(TokenController.class);

    @Autowired
    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }


    /**
     * L1 Diagrams - request_foreign_token()
     * TODO R3
     */
    @RequestMapping(value = AAMConstants.AAM_REQUEST_FOREIGN_TOKEN, method = RequestMethod.POST)
    public ResponseEntity<?> requestForeignToken(@RequestHeader(AAMConstants.TOKEN_HEADER_NAME) String token) {

        /*
        Token(s) Validation through challenge-response (client-side)
        Validate Token(s)
        Check-Revocation Procedures (client)
        Attribute Mapping Function
        */

        Token foreignToken = null;
        HttpHeaders headers = new HttpHeaders();
        try {
            foreignToken = new Token(tokenService.exchangeForForeignToken(token).getToken());
        } catch (TokenValidationException e) {
            return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
        } catch (JWTCreationException e) {
            log.error(e);
            return new ResponseEntity<>(headers, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        headers.add(AAMConstants.TOKEN_HEADER_NAME, foreignToken.getToken());

        /* Finally issues and return foreign_token */
        return new ResponseEntity<>(headers, HttpStatus.OK);
    }

    /**
     * L1 Diagrams - check_token_revocation()
     * TODO R3
     */
    @RequestMapping(value = AAMConstants.AAM_CHECK_HOME_TOKEN_REVOCATION, method = RequestMethod.POST)
    public ResponseEntity<CheckRevocationResponse> checkHomeTokenRevocation(@RequestHeader(AAMConstants
            .TOKEN_HEADER_NAME) String tokenString) {
        Token token;
        try {
            token = new Token(tokenString);
        } catch (TokenValidationException e) {
            return new ResponseEntity<>(new CheckRevocationResponse(ValidationStatus.INVALID), HttpStatus.OK);
        }
        return new ResponseEntity<>(tokenService.checkHomeTokenRevocation(token), HttpStatus.OK);
    }
}
