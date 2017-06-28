package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import eu.h2020.symbiote.security.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.interfaces.ICoreServices;
import eu.h2020.symbiote.security.interfaces.IToken;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.services.TokenService;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

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
public class TokenController implements IToken {

    private final TokenService tokenService;
    private Log log = LogFactory.getLog(TokenController.class);
    private ICoreServices coreServices;
    private String deploymentId = "";
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;

    @Value("${symbiote.coreaam.url:localhost}")
    private String coreAAMAddress = "";

    @Autowired
    public TokenController(TokenService tokenService, ICoreServices coreServices, RegistrationManager
            registrationManager) {
        this.tokenService = tokenService;
        this.coreServices = coreServices;
        this.deploymentId = registrationManager.getAAMInstanceIdentifier();
        this.deploymentType = registrationManager.getDeploymentType();
    }

    public ResponseEntity<?> requestFederatedHomeToken(@RequestHeader(AAMConstants.TOKEN_HEADER_NAME) String
                                                               receivedTokenString) {
        HttpHeaders headers = new HttpHeaders();
        Token federatedHomeToken;
        try {
            // validating the string from request
            Token receivedToken = new Token(receivedTokenString);

            // TODO R3 Token(s) Validation through challenge-response (client-side)

            // checking revocation in relevant AAM
            if (receivedToken.getClaims().getIssuer().equals(deploymentId)) {
                log.debug("Someone tried issuing a federated token using a home token");
                return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
            } else {
                List<AAM> availableAAMs;
                if (deploymentType == IssuingAuthorityType.CORE) {
                    // if Core AAM then we know the available AAMs
                    availableAAMs = coreServices.getAvailableAAMs().getBody();
                } else {
                    // a PAAM needs to fetch them from core
                    RestTemplate restTemplate = new RestTemplate();
                    ResponseEntity<List<AAM>> response = restTemplate.exchange(coreAAMAddress + AAMConstants
                            .AAM_GET_AVAILABLE_AAMS, HttpMethod.GET, null, new ParameterizedTypeReference<List<AAM>>() {
                    });
                    availableAAMs = response.getBody();
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

                MultiValueMap<String, String> headersMap = new LinkedMultiValueMap<>();
                headersMap.add(AAMConstants.TOKEN_HEADER_NAME, receivedToken.toString());
                HttpEntity<String> request = new HttpEntity<>(null, headersMap);
                RestTemplate restTemplate = new RestTemplate();
                ResponseEntity<CheckRevocationResponse> status = restTemplate.postForEntity(remoteAAM.getAamAddress() +
                        AAMConstants.AAM_VALIDATE, request, CheckRevocationResponse.class);

                ValidationStatus validationStatus = ValidationStatus.valueOf(status.getBody().getStatus());
                if (validationStatus != ValidationStatus.VALID) {
                    log.debug("Couldn't find AAM related with the given token");
                    return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
                }
            }
            federatedHomeToken = new Token(tokenService.createFederatedHomeTokenForForeignToken(receivedTokenString)
                    .getToken());
        } catch (ValidationException e) {
            log.error(e);
            return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
        } catch (JWTCreationException e) {
            log.error(e);
            return new ResponseEntity<>(headers, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        headers.add(AAMConstants.TOKEN_HEADER_NAME, federatedHomeToken.getToken());

        /* Finally issues and return foreign_token */
        return new ResponseEntity<>(headers, HttpStatus.OK);
    }

    //L1 Diagrams - login()
    public ResponseEntity<?> login(@RequestBody Credentials user) {
        try {
            Token token = tokenService.login(user);
            HttpHeaders headers = new HttpHeaders();
            headers.add(AAMConstants.TOKEN_HEADER_NAME, token.getToken());
            return new ResponseEntity<>(headers, HttpStatus.OK);
        } catch (SecurityException e) {
            log.error(e);
            return new ResponseEntity<>(new ErrorResponseContainer(e.getErrorMessage(), e
                    .getStatusCode().ordinal()), e.getStatusCode());
        }
    }
}
