package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IRevoke;
import eu.h2020.symbiote.security.services.RevocationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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
    private static final Log log = LogFactory.getLog(RevocationController.class);
    private RevocationService revocationService;

    @Autowired
    public RevocationController(RevocationService revocationService) {
        this.revocationService = revocationService;
    }

    @Override
    public ResponseEntity<String> revoke(@RequestBody RevocationRequest revocationRequest) {
        try {
            revocationService.revoke(revocationRequest);
            return ResponseEntity.status(HttpStatus.OK).body("TODO");
        } catch (Exception e) {
            return null;
        }

    }
}
