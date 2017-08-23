package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationResponse;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IRevoke;
import eu.h2020.symbiote.security.services.RevocationService;
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

@RestController
public class RevocationController implements IRevoke {
    private RevocationService revocationService;

    @Autowired
    public RevocationController(RevocationService revocationService) {
        this.revocationService = revocationService;
    }

    @Override
    public ResponseEntity<String> revoke(@RequestBody RevocationRequest revocationRequest) {
        RevocationResponse revocationResponse = revocationService.revoke(revocationRequest);
        return ResponseEntity.status(revocationResponse.getStatus()).body(String.valueOf(revocationResponse.isRevoked()));
    }
}
