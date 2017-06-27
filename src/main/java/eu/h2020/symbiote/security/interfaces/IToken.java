package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.payloads.Credentials;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Access to other services offered by TokenController.
 *
 * @author Piotr Kicki (PSNC)
 */
public interface IToken {
    /**
     * L1 Diagrams - request_foreign_token()
     * TODO R3
     */
    @PostMapping(value = AAMConstants.AAM_REQUEST_FOREIGN_TOKEN)
    ResponseEntity<?> requestFederatedHomeToken(@RequestHeader(AAMConstants.TOKEN_HEADER_NAME) String
                                                        receivedTokenString);

    //L1 Diagrams - login()
    @PostMapping(value = AAMConstants.AAM_LOGIN)
    ResponseEntity<?> login(@RequestBody Credentials user);
}
