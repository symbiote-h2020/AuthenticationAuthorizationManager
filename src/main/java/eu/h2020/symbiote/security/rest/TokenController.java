package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.SecurityHandler;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.exceptions.aam.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.aam.TokenValidationException;
import eu.h2020.symbiote.security.interfaces.ICoreServices;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.services.TokenService;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;


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
    private ICoreServices coreServices;
    private RegistrationManager registrationManager;
    private String deploymentId = "";
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;

    @Value("${symbiote.coreaam.url:localhost}")
    private String coreAAMAddress = "";

    @Autowired
    public TokenController(TokenService tokenService, ICoreServices coreServices, RegistrationManager
            registrationManager) {
        this.tokenService = tokenService;
        this.coreServices = coreServices;
        this.registrationManager = registrationManager;
        this.deploymentId = registrationManager.getAAMInstanceIdentifier();
        this.deploymentType = registrationManager.getDeploymentType();
    }

    /**
     * L1 Diagrams - request_foreign_token()
     * TODO R3
     */
    @RequestMapping(value = AAMConstants.AAM_REQUEST_FOREIGN_TOKEN, method = RequestMethod.POST)
    public ResponseEntity<?> requestFederatedHomeToken(@RequestHeader(AAMConstants.TOKEN_HEADER_NAME) String
                                                               receivedTokenString) {
        HttpHeaders headers = new HttpHeaders();
        Token federatedHomeToken = null;
        try {
            // validating the string from request
            Token receivedToken = new Token(receivedTokenString);

            // TODO R3 Token(s) Validation through challenge-response (client-side)

            // checking revocation in relevant AAM
            if (receivedToken.getClaims().getIssuer().equals(deploymentId)) {
                log.debug("Someone tried issuing a federated token using a home token");
                return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
            } else {
                SecurityHandler securityHandler = new SecurityHandler(coreAAMAddress);
                List<AAM> availableAAMs;
                if (deploymentType == IssuingAuthorityType.CORE) {
                    // if Core AAM then we know the available AAMs
                    availableAAMs = coreServices.getAvailableAAMs().getBody();
                } else {
                    // a PAAM needs to fetch them from core
                    availableAAMs = securityHandler.getAvailableAAMs();
                }
                AAM remoteAAM = null;
                for (AAM availableAAM : availableAAMs) {
                    if (receivedToken.getClaims().getIssuer().equals(availableAAM.getAamInstanceId())) {
                        remoteAAM = availableAAM;
                        break;
                    }
                }
                if (remoteAAM == null) {
                    log.debug("Couldn't find AAM related with the given token");
                    return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
                }
                ValidationStatus validationStatus = securityHandler.verifyPlatformToken(remoteAAM, receivedToken);
                if (validationStatus != ValidationStatus.VALID) {
                    log.debug("Couldn't find AAM related with the given token");
                    return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
                }
            }
            federatedHomeToken = new Token(tokenService.createFederatedHomeTokenForForeignToken(receivedTokenString)
                    .getToken());
        } catch (TokenValidationException e) {
            log.debug(e);
            return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
        } catch (JWTCreationException | SecurityHandlerException e) {
            log.error(e);
            return new ResponseEntity<>(headers, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        headers.add(AAMConstants.TOKEN_HEADER_NAME, federatedHomeToken.getToken());

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
