package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import io.swagger.annotations.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes services allowing SymbIoTe actors (users) to revoke their tokens and certificates
 *
 * @author Jakub Toczek (PSNC)
 */
@Api(value = "/docs/revoke", description = "Exposes services allowing SymbIoTe actors (users) to revoke their tokens and certificates")
public interface IRevoke {
    /**
     * Exposes a service that allows users to revoke their client certificates and tokens.
     *
     * @param revocationRequest required to revoke. Depending on it's fields, token or certificate can be revoked.
     * @return ResponseEntity<String> where as header HTTP status is sent and in body true/false depending on revocation status
     */
    @ApiOperation(value = "Allows users to revoke their client certificates and tokens")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Request contains invalid arguments"),
            @ApiResponse(code = 401, message = "Incorrect credentials were provided")})
    @PostMapping(value = SecurityConstants.AAM_REVOKE, consumes = "application/json")
    ResponseEntity<String> revoke(
            @ApiParam(name = "Revocation Request", value = "Depending on it's fields, token or certificate can be revoked", required = true)
            @RequestBody RevocationRequest revocationRequest);
}
