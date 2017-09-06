package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationResponse;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IRevoke;
import eu.h2020.symbiote.security.services.RevocationService;
import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated with revoking certificates and tokens.
 *
 * @author Jakub Toczek (PSNC)
 * @see RevocationService
 */
@Api(value = "/docs/revoke", description = "Exposes services allowing SymbIoTe actors (users) to revoke their tokens and certificates")
@RestController
public class RevocationController implements IRevoke {
    private RevocationService revocationService;

    @Autowired
    public RevocationController(RevocationService revocationService) {
        this.revocationService = revocationService;
    }

    @Override
    @ApiOperation(value = "Allows users to revoke their client certificates and tokens")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Request contains invalid arguments"),
            @ApiResponse(code = 401, message = "Incorrect credentials were provided")})
    public ResponseEntity<String> revoke(
            @RequestBody
            @ApiParam(name = "Revocation Request", value = "Depending on it's fields, token or certificate can be revoked", required = true)
                    RevocationRequest revocationRequest) {
        RevocationResponse revocationResponse = revocationService.revoke(revocationRequest);
        return ResponseEntity.status(revocationResponse.getStatus()).body(String.valueOf(revocationResponse.isRevoked()));
    }
}
