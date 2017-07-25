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
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.util.Map;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to token objects in Cloud
 * AAM component.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see GetTokenService
 */
@Component
//@RestController
@Path(value = "/test/caam")
public class GetTokenController implements IGetToken {

    private final GetTokenService getTokenService;
    private Log log = LogFactory.getLog(GetTokenController.class);
    private IAAMServices coreServices;
    private String deploymentId = "";
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;

    @Value("${symbiote.coreaam.url:localhost}")
    private String coreAAMAddress = "";

    @Autowired
    public GetTokenController(GetTokenService getTokenService, IAAMServices coreServices, CertificationAuthorityHelper
            certificationAuthorityHelper) {
        this.getTokenService = getTokenService;
        this.coreServices = coreServices;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
    }



    public Response getForeignToken(@HeaderParam(SecurityConstants.TOKEN_HEADER_NAME) String
                                                     homeToken) {
        HttpHeaders headers = new HttpHeaders();
        Token federatedHomeToken;
        try {
            // validating the string from request
            Token receivedToken = new Token(homeToken);

            // checking revocation in relevant AAM
            if (receivedToken.getClaims().getIssuer().equals(deploymentId)) {
                log.debug("Someone tried issuing a federated token using a home token");
                return //new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
                Response.status(Response.Status.BAD_REQUEST).entity(headers).build();
            } else {
                Map<String, AAM> availableAAMs;
                if (deploymentType == IssuingAuthorityType.CORE) {
                    // if Core AAM then we know the available AAMs
                    availableAAMs = coreServices.getAvailableAAMs();
                } else {
                    // a PAAM needs to fetch them from core
                    RestTemplate restTemplate = new RestTemplate();
                    Map<String, AAM> response = restTemplate.exchange(coreAAMAddress + SecurityConstants
                            .AAM_GET_AVAILABLE_AAMS, HttpMethod.GET, null, new ParameterizedTypeReference<Map<String,
                            AAM>>() {
                    }).getBody();
                    availableAAMs = response;
                }
                AAM remoteAAM = availableAAMs.get(receivedToken.getClaims().getIssuer());
                if (remoteAAM == null) {
                    log.debug("Couldn't find AAM related with the given token");
                    return //new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
                            Response.status(Response.Status.BAD_REQUEST).entity(headers).build();
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
                    return //new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
                            Response.status(Response.Status.BAD_REQUEST).entity(headers).build();
                }
            }
            federatedHomeToken = new Token(getTokenService.createFederatedHomeTokenForForeignToken(homeToken)
                    .getToken());
        } catch (ValidationException e) {
            log.error(e);
            return //new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
                    Response.status(Response.Status.BAD_REQUEST).entity(headers).build();
        } catch (JWTCreationException e) {
            log.error(e);
            return //new ResponseEntity<>(headers, HttpStatus.INTERNAL_SERVER_ERROR);
                    Response.status(Response.Status.BAD_REQUEST).entity(headers).build();
        }
        headers.add(SecurityConstants.TOKEN_HEADER_NAME, federatedHomeToken.getToken());

        /* Finally issues and return foreign_token */
        return //new ResponseEntity<>(headers, HttpStatus.OK);
                Response.status(Response.Status.BAD_REQUEST).entity(headers).build();
    }

    @Override
    public Response getGuestToken() {
        // TODO R3 Jakub
        return null;
    }

    //L1 Diagrams - getHomeToken()
    @POST
    //@Consumes(MediaType.APPLICATION_JSON)
    @Path(SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_GET_HOME_TOKEN)
    public Response getHomeToken(@Context Credentials user) {
        log.info("MARKER1");
        try {
            Token token = getTokenService.login(user);
            HttpHeaders headers = new HttpHeaders();
            headers.add(SecurityConstants.TOKEN_HEADER_NAME, token.getToken());
            //return new ResponseEntity<>(headers, HttpStatus.OK);
            return Response.status(Response.Status.OK).entity(headers).build();
        } catch (SecurityException e) {
            log.error(e);
           /* return new ResponseEntity<String>(new ErrorResponseContainer(e.getErrorMessage(), e
                    .getStatusCode().ordinal()).toString(), e.getStatusCode());*/
           return Response.status(Response.Status.NOT_ACCEPTABLE).entity(new ErrorResponseContainer(e.getErrorMessage(), e
                   .getStatusCode().ordinal())).build();
        }
    }
}
