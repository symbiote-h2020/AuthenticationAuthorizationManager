package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import net.lingala.zip4j.exception.ZipException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * Access to other services offered by ApplicationRegistrationController.
 *
 * @author Piotr Kicki (PSNC)
 */
public interface IRegistration {
    @PreAuthorize("isAuthenticated()")
    @PostMapping(value = AAMConstants.AAM_ADMIN_PATH + "/registration")
    ResponseEntity<?> register(@RequestParam Map<String, String> requestMap, HttpServletResponse response)
            throws SecurityException, IOException, ZipException;

    @PostMapping(value = AAMConstants.AAM_PUBLIC_PATH + "/register")
    ResponseEntity<?> register(@RequestBody UserRegistrationRequest request);

    @PostMapping(value = AAMConstants.AAM_PUBLIC_PATH + "/unregister")
    ResponseEntity<?> unregister(@RequestBody UserRegistrationRequest request);
}
