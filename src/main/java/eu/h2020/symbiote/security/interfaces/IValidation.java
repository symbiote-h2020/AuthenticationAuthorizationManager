package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Access to other services offered by ValidationController.
 *
 * @author Piotr Kicki (PSNC)
 */
public interface IValidation {
    /**
     * L1 Diagrams - check_token_revocation()
     * TODO R3 refactor to ValidationStatus validate(Token String);
     */
    @RequestMapping(value = AAMConstants.AAM_CHECK_HOME_TOKEN_REVOCATION, method = RequestMethod.POST)
    ResponseEntity<CheckRevocationResponse> checkHomeTokenRevocation(@RequestHeader(AAMConstants
            .TOKEN_HEADER_NAME) String tokenString);

}
