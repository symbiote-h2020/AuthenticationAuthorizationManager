package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IValidateClientCertificate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * @JT please review
 */
@RestController
public class ValidateClientCertificate implements IValidateClientCertificate {

    /**
     * @param foreignToken - Foreign token which validity is to be confirmed
     * @return Validation status of operation
     */
    public ResponseEntity<ValidationStatus> confirmClientCertificateValidity(String foreignToken) {

        /*
        * TODO -> Implement
        */

        return ResponseEntity.ok(ValidationStatus.VALID);
    }
}
