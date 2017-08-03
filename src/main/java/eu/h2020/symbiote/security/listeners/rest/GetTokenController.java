package eu.h2020.symbiote.security.listeners.rest;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.interfaces.IGetToken;
import eu.h2020.symbiote.security.services.GetTokenService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to token objects in Cloud
 * AAM component.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see GetTokenService
 */
@RestController
public class GetTokenController implements IGetToken {

    private final GetTokenService getTokenService;
    private Log log = LogFactory.getLog(GetTokenController.class);

    @Autowired
    public GetTokenController(GetTokenService getTokenService) {
        this.getTokenService = getTokenService;
    }

    public ResponseEntity<String> getForeignToken(@RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String remoteHomeToken,
                                                  @RequestHeader(name = SecurityConstants.CERTIFICATE_HEADER_NAME,
                                                          defaultValue = "") String certificate) {
        HttpHeaders headers = new HttpHeaders();
        Token foreignToken;
        try {
            foreignToken = getTokenService.getForeignToken(new Token(remoteHomeToken), certificate);
        } catch (ValidationException e) {
            log.error(e);
            return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
        } catch (JWTCreationException e) {
            log.error(e);
            return new ResponseEntity<>(headers, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        headers.add(SecurityConstants.TOKEN_HEADER_NAME, foreignToken.getToken());
        return new ResponseEntity<>(headers, HttpStatus.OK);
    }

    public ResponseEntity<String> getGuestToken() {
        try {
            Token token = getTokenService.getGuestToken();
            HttpHeaders headers = new HttpHeaders();
            headers.add(SecurityConstants.TOKEN_HEADER_NAME, token.getToken());
            return new ResponseEntity<>(headers, HttpStatus.OK);
        } catch (SecurityException e) {
            log.error(e);
            return new ResponseEntity<>(e.getErrorMessage(), e.getStatusCode());
        }
    }

    //L1 Diagrams - getHomeToken()
    public ResponseEntity<String> getHomeToken(@RequestBody String loginRequest) {
        //  Temporary - Removes additional '"' coming from encoder
        String checked = loginRequest;
        if (loginRequest.startsWith("\"") && loginRequest.endsWith("\""))
            checked = loginRequest.replaceAll("\"", "");
        try {
            Token token = getTokenService.getHomeToken(checked);
            HttpHeaders headers = new HttpHeaders();
            headers.add(SecurityConstants.TOKEN_HEADER_NAME, token.getToken());
            return new ResponseEntity<>(headers, HttpStatus.OK);
        } catch (SecurityException e) {
            log.error(e);
            return new ResponseEntity<>(e.getErrorMessage(), e.getStatusCode());
        } catch (Exception e) {
            log.error(e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }
}