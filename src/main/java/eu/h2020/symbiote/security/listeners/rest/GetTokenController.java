package eu.h2020.symbiote.security.listeners.rest;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.interfaces.IAAMServices;
import eu.h2020.symbiote.security.communication.interfaces.IGetToken;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
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

import java.util.Map;


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
    // todo use a service, not a rest controller!
    private IAAMServices coreServicesController;
    private String deploymentId = "";
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;

    @Value("${symbiote.coreaam.url:localhost}")
    private String coreAAMAddress = "";

    @Autowired
    public GetTokenController(GetTokenService getTokenService, IAAMServices coreServices, CertificationAuthorityHelper
            certificationAuthorityHelper) {
        this.getTokenService = getTokenService;
        this.coreServicesController = coreServices;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
    }

    public ResponseEntity<String> getForeignToken(@RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String remoteHomeToken,
                                                  @RequestHeader(name = SecurityConstants.CERTIFICATE_HEADER_NAME,
                                                          defaultValue = "") String certificate) {
        // todo use certificate for validation
        HttpHeaders headers = new HttpHeaders();
        Token foreignToken;
        try {
            // validating the string from request
            Token receivedToken = new Token(remoteHomeToken);

            // checking revocation in relevant AAM
            if (receivedToken.getClaims().getIssuer().equals(deploymentId)) {
                log.debug("Someone tried issuing a foreign token using a home token");
                return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
            } else {
                // TODO call validation service inside the service
                Map<String, AAM> availableAAMs;
                if (deploymentType == IssuingAuthorityType.CORE) {
                    // if Core AAM then we know the available AAMs
                    availableAAMs = coreServicesController.getAvailableAAMs().getBody().getAvailableAAMs();
                } else {
                    // a PAAM needs to fetch them from core
                    RestTemplate restTemplate = new RestTemplate();
                    availableAAMs = restTemplate.exchange(coreAAMAddress + SecurityConstants
                            .AAM_GET_AVAILABLE_AAMS, HttpMethod.GET, null, new ParameterizedTypeReference<Map<String,
                            AAM>>() {
                    }).getBody();
                    ;
                }
                AAM remoteAAM = availableAAMs.get(receivedToken.getClaims().getIssuer());
                if (remoteAAM == null) {
                    log.debug("Couldn't find AAM related with the given token");
                    return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
                }

                MultiValueMap<String, String> headersMap = new LinkedMultiValueMap<>();
                headersMap.add(SecurityConstants.TOKEN_HEADER_NAME, receivedToken.toString());
                HttpEntity<String> request = new HttpEntity<>(null, headersMap);
                RestTemplate restTemplate = new RestTemplate();
                ResponseEntity<ValidationStatus> status = restTemplate.postForEntity(remoteAAM.getAamAddress() +
                        SecurityConstants.AAM_VALIDATE, request, ValidationStatus.class);

                ValidationStatus validationStatus = status.getBody();
                if (validationStatus != ValidationStatus.VALID) {
                    log.debug("Couldn't find AAM related with the given token");
                    return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
                }
            }
            foreignToken = getTokenService.getForeignToken(remoteHomeToken);
        } catch (ValidationException e) {
            log.error(e);
            return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
        } catch (JWTCreationException e) {
            log.error(e);
            return new ResponseEntity<>(headers, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        headers.add(SecurityConstants.TOKEN_HEADER_NAME, foreignToken.getToken());

        /* Finally issues and return foreign_token */
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