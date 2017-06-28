package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Access to other services offered by ApplicationRegistrationController.
 *
 * @author Piotr Kicki (PSNC)
 */
public interface IRegistration {


    @PostMapping(value = AAMConstants.AAM_PUBLIC_PATH + "/register")
    ResponseEntity<?> register(@RequestBody UserRegistrationRequest request);

    @PostMapping(value = AAMConstants.AAM_PUBLIC_PATH + "/unregister")
    ResponseEntity<?> unregister(@RequestBody UserRegistrationRequest request);
}
