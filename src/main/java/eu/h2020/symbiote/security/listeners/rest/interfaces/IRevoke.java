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

public interface IRevoke {
    /**
     * Exposes a service that allows users to revoke their client certificates and tokens.
     *
     * @param revocationRequest required to revoke. Depending it's fields, token or certificate can be revoked.
     * @return TODO
     */
    @PostMapping(value = SecurityConstants.AAM_REVOKE, consumes = "application/json")
    ResponseEntity<String> revoke(@RequestBody RevocationRequest revocationRequest);
}
