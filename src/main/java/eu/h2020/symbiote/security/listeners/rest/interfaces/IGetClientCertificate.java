package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes a service that allows users to acquire their client certificates.
 *
 * @author Maks Marcinowski (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Api(value = "docs/getclientcertificate", description = "Used to receive Client's Certificate")
public interface IGetClientCertificate {
    /**
     * @param certificateRequest required to issue a certificate for given (username, clientId) tupple.
     * @return the certificate issued using the provided CSR in PEM format
     */
    @ApiOperation(value = "Allows retrieving of Client's Certificate")
    @PostMapping(value = SecurityConstants.AAM_GET_CLIENT_CERTIFICATE, consumes = "application/json")
    @ApiResponse(code = 500, message = "Could not create Client Certificate")
    ResponseEntity<String> getClientCertificate(
            @RequestBody
            @ApiParam(name = "Certificate Request", value = "Request required to issue a certificate for given (username, clientId) tupple", required = true)
                    CertificateRequest certificateRequest);
}