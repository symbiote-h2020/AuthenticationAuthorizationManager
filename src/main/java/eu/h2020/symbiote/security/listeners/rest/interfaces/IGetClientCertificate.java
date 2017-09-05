package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
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
    @ApiOperation(value = "Allows retrieving of CLient's Certificate")
    @PostMapping(value = SecurityConstants.AAM_GET_CLIENT_CERTIFICATE, consumes = "application/json")
    @ApiImplicitParams({@ApiImplicitParam(name = "username", value = "User's username", required = true, dataType = "String", paramType = "body"),
            @ApiImplicitParam(name = "password", value = "User's password", required = true, dataType = "String", paramType = "body"),
            @ApiImplicitParam(name = "ID", value = "User's ID", required = true, dataType = "String", paramType = "body"),
            @ApiImplicitParam(name = "Client's CSR", value = "Client's CSR in PEM Format", required = true, dataType = "String", paramType = "body")})

    ResponseEntity<String> getClientCertificate(@RequestBody CertificateRequest certificateRequest);
}