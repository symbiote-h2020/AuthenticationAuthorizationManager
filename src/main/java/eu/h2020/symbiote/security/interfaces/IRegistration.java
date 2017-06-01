package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.exceptions.AAMException;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import net.lingala.zip4j.exception.ZipException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
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
    @RequestMapping(value = "/registration", method = RequestMethod.POST)
    ResponseEntity<?> register(@RequestParam Map<String, String> requestMap, HttpServletResponse response)
            throws AAMException, IOException, ZipException;

    @RequestMapping(value = "/register", method = RequestMethod.POST)
    ResponseEntity<?> register(@RequestBody UserRegistrationRequest request);

    @RequestMapping(value = "/unregister", method = RequestMethod.POST)
    ResponseEntity<?> unregister(@RequestBody UserRegistrationRequest request);
}
