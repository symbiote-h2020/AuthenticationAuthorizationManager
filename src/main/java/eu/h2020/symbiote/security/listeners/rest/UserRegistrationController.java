package eu.h2020.symbiote.security.listeners.rest;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.interfaces.IRegistration;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.interfaces.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.interfaces.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.UsersManagementService;
import net.lingala.zip4j.exception.ZipException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Map;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web service associated to user/app registration
 * service in Cloud AAM component.
 *
 * TODO R3... can we drop it at all in favor of the AMQP interface?
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see GetTokenService
 */
@Component
//@RestController
public class UserRegistrationController implements IRegistration {

    private static Log log = LogFactory.getLog(UserRegistrationController.class);
    private final UsersManagementService registrationService;

    @Autowired
    public UserRegistrationController(UsersManagementService registrationService) {
        this.registrationService = registrationService;
    }

   //@PreAuthorize("isAuthenticated()")
    //@PostMapping(value = SecurityConstants.AAM_ADMIN_PATH + "/web_register")
    @POST
    @Path(value = SecurityConstants.AAM_ADMIN_PATH + "/web_register")
    //@Consumes(MediaType.APPLICATION_JSON)
    //@Produces(MediaType.APPLICATION_JSON)
    public Response register(@Context Map<String, String> requestMap,@Context HttpServletResponse response)//@RequestParam
            throws SecurityException, IOException, ZipException {
        UserManagementRequest request = new UserManagementRequest();
        // TODO R3 incorporate federated Id (and possibly recovery e-mail)
        request.setUserDetails(new UserDetails(new Credentials(requestMap.get("username"), requestMap.get("password")
        ), "R3-feature", "not-applicable", UserRole.USER));
        registrationService.register(request);

        return //new ResponseEntity<HttpServletResponse>(HttpStatus.OK);
                Response.status(Response.Status.OK).build();
    }
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(  UserManagementRequest request) {//RequestBody
        try {
            return //new ResponseEntity<>(registrationService.authRegister(request), HttpStatus.OK);
            Response.status(Response.Status.OK).entity(registrationService.authRegister(request)).build();
        } catch (SecurityException e) {
            log.error(e);
            return //new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e
                   // .getStatusCode().ordinal()), e.getStatusCode());
            Response.status(Response.Status.NOT_ACCEPTABLE).entity(new ErrorResponseContainer(e.getErrorMessage(),
                    e.getStatusCode().ordinal())).build();
        }
    }
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response unregister(UserManagementRequest request) {
        try {
            registrationService.authUnregister(request);
            return //new ResponseEntity<>(HttpStatus.OK);
            Response.status(Response.Status.OK).build();
        } catch (SecurityException e) {
            log.error(e);
            return /*new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e
                    .getStatusCode().ordinal()), e.getStatusCode());*/
            Response.status(Response.Status.NOT_ACCEPTABLE).entity(new ErrorResponseContainer(e.getErrorMessage(), e
                    .getStatusCode().ordinal())).build();
        }
    }
}