package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.payloads.Credentials;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

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
    @RequestMapping(value = AAMConstants.AAM_REQUEST_FOREIGN_TOKEN, method = RequestMethod.POST)
    ResponseEntity<?> requestFederatedHomeToken(@RequestHeader(AAMConstants.TOKEN_HEADER_NAME) String
                                                        receivedTokenString);

    //L1 Diagrams - login()
    @RequestMapping(value = AAMConstants.AAM_LOGIN, method = RequestMethod.POST)
    ResponseEntity<?> login(@RequestBody Credentials user);
}
