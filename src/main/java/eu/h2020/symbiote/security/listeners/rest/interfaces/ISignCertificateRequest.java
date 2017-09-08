package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes a service that allows users to acquire their clients'/components'/AAMs' certificates.
 *
 * @author Maks Marcinowski (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */

public interface ISignCertificateRequest {
    /**
     * @param certificateRequest required to sign a certificate request for given (username, clientId) tupple.
     * @return the certificate issued using the provided CSR in PEM format
     */
    @PostMapping(value = SecurityConstants.AAM_SIGN_CERTIFICATE_REQUEST, consumes = "application/json")
    ResponseEntity<String> signCertificateRequest(@RequestBody CertificateRequest certificateRequest);
}