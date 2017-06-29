package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Access to other services offered by ValidationController.
 *
 * @author Piotr Kicki (PSNC)
 */

public interface IValidation {
    /**
     * TODO R3 refactor to ValidationStatus validate(Token String);
     */
    @PostMapping(value = AAMConstants.AAM_PUBLIC_PATH + AAMConstants.AAM_VALIDATE)
    ResponseEntity<CheckRevocationResponse> validate(@RequestHeader(AAMConstants.TOKEN_HEADER_NAME) String tokenString,
                                                     @RequestHeader(name = AAMConstants.CERTIFICATE_HEADER_NAME,
                                                             defaultValue = "") String certificateString);
}
