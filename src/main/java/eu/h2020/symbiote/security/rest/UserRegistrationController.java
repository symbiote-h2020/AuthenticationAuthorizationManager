package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import eu.h2020.symbiote.security.interfaces.IRegistration;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.payloads.UserDetails;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import eu.h2020.symbiote.security.services.TokenService;
import eu.h2020.symbiote.security.services.UserRegistrationService;
import net.lingala.zip4j.exception.ZipException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web service associated to user/app registration
 * service in Cloud AAM component.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see TokenService
 */
@RestController
public class UserRegistrationController implements IRegistration {

    private static Log log = LogFactory.getLog(UserRegistrationController.class);
    private final UserRegistrationService registrationService;

    @Autowired
    public UserRegistrationController(UserRegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping(value = AAMConstants.AAM_ADMIN_PATH + "/web_register")
    ResponseEntity<?> register(@RequestParam Map<String, String> requestMap, HttpServletResponse response)
            throws SecurityException, IOException, ZipException {
        UserRegistrationRequest request = new UserRegistrationRequest();
        // TODO R3 incorporate federated Id (and possibly recovery e-mail)
        request.setUserDetails(new UserDetails(new Credentials(requestMap.get("username"), requestMap.get("password")
        ), "R3-feature", "not-applicable", UserRole.USER));
        registrationService.register(request);

        return new ResponseEntity<HttpServletResponse>(HttpStatus.OK);
    }

    public ResponseEntity<?> register(@RequestBody UserRegistrationRequest request) {
        try {
            return new ResponseEntity<>(registrationService.authRegister(request), HttpStatus.OK);
        } catch (SecurityException e) {
            log.error(e);
            return new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e
                    .getStatusCode().ordinal()), e.getStatusCode());
        }
    }

    public ResponseEntity<?> unregister(@RequestBody UserRegistrationRequest request) {
        try {
            registrationService.authUnregister(request);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (SecurityException e) {
            log.error(e);
            return new ResponseEntity<ErrorResponseContainer>(new ErrorResponseContainer(e.getErrorMessage(), e
                    .getStatusCode().ordinal()), e.getStatusCode());
        }
    }
}