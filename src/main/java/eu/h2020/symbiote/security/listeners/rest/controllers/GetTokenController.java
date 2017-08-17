package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IGetToken;
import eu.h2020.symbiote.security.services.GetTokenService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated with acquiring tokens.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
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
                                                  @RequestHeader(name = SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificate,
                                                  @RequestHeader(name = SecurityConstants.AAM_CERTIFICATE_HEADER_NAME, defaultValue = "") String aamCertificate) {
        HttpHeaders headers = new HttpHeaders();
        Token foreignToken;
        try {
            foreignToken = getTokenService.getForeignToken(new Token(remoteHomeToken), clientCertificate, aamCertificate);
        } catch (ValidationException e) {
            log.error(e);
            return new ResponseEntity<>(headers, e.getStatusCode());
        } catch (JWTCreationException e) {
            // todo have a different code here
            log.error(e);
            return new ResponseEntity<>(headers, e.getStatusCode());
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
        } catch (JWTCreationException e) {
            log.error(e);
            return new ResponseEntity<>(e.getErrorMessage(), e.getStatusCode());
        }
    }

    //L1 Diagrams - getHomeToken()
    public ResponseEntity<String> getHomeToken(@RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String loginRequest) {
        try {
            Token token = getTokenService.getHomeToken(loginRequest);
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