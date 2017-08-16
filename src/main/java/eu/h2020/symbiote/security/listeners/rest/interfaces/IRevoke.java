package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

public interface IRevoke {
    /**
     * Exposes a service that allows users to revokeHomeToken their client certificates.
     *
     * @param revocationRequest required to revokeHomeToken a certificate.
     * @return the certificate issued using the provided CSR in PEM format
     */
    @PostMapping(value = SecurityConstants.AAM_REVOKE, consumes = "application/json")
    ResponseEntity<String> revoke(@RequestBody RevocationRequest revocationRequest);
}
