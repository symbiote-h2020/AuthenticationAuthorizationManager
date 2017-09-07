package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IGetToken;
import eu.h2020.symbiote.security.services.GetTokenService;
import io.swagger.annotations.*;
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
@Api(value = "/docs/gettokenservice", description = "Exposes services responsible for providing Tokens")
public class GetTokenController implements IGetToken {

    private final GetTokenService getTokenService;
    private Log log = LogFactory.getLog(GetTokenController.class);

    @Autowired
    public GetTokenController(GetTokenService getTokenService) {
        this.getTokenService = getTokenService;
    }

    @ApiOperation(value = "Issues a Foreign Token")
    @ApiResponses({
            @ApiResponse(code = 401, message = "Received token could not be validated"),
            @ApiResponse(code = 500, message = "Server failed to create Foreign Token")})
    public ResponseEntity<String> getForeignToken(
            @ApiParam(value = "Token that will be exchanged for Foreign Token", required = true)
            @RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String remoteHomeToken,
            @ApiParam(value = "in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios", required = false)
            @RequestHeader(name = SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificate,
            @ApiParam(value = "in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios", required = false)
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

    @ApiOperation(value = "Issues a Guest Token")
    @ApiResponse(code = 500, message = "Could not create Guest Token")
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
    @ApiOperation(value = "Issues a Home Token")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Received token was malformed"),
            @ApiResponse(code = 401, message = "Incorrect Credentials were provided"),
            @ApiResponse(code = 500, message = "Server failed to create Home Token")})
    public ResponseEntity<String> getHomeToken(
            @RequestHeader(SecurityConstants.TOKEN_HEADER_NAME)
            @ApiParam(value = "JWS built in accordance to Symbiote Security Cryptohelper", required = true) String loginRequest) {
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