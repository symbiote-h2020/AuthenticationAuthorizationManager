package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes a service that allows users to acquire their client certificates.
 *
 * @author Maks Marcinowski (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IGetClientCertificate {
    /**
     * Exposes a service that allows users to acquire their client certificates.
     *
     * @param certificateRequest required to issue a certificate for given (username, clientId) tupple.
     * @return the certificate issued using the provided CSR in PEM format
     */
    @PostMapping(value = SecurityConstants.AAM_GET_CLIENT_CERTIFICATE, consumes = "application/json")
    ResponseEntity<String> getClientCertificate(@RequestBody CertificateRequest certificateRequest);
}