package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes services allowing SymbIoTe actors (users) to revoke their tokens and certificates
 *
 * @author Jakub Toczek (PSNC)
 */
public interface IRevokeCredentials {
    /**
     * Exposes a service that allows users to revoke their client certificates and tokens.
     *
     * @param revocationRequest required to revoke. Depending on it's fields, token or certificate can be revoked.
     * @return ResponseEntity<String> where as header HTTP status is sent and in body true/false depending on revocation status
     */
    @PostMapping(value = SecurityConstants.AAM_REVOKE_CREDENTIALS, consumes = "application/json")
    ResponseEntity<String> revoke(@RequestBody RevocationRequest revocationRequest);
}
