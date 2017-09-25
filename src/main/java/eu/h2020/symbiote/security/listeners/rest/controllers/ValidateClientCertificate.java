package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IValidateClientCertificate;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @JT please review
 */
@RestController
public class ValidateClientCertificate implements IValidateClientCertificate {

    private final ValidationHelper validationHelper;

    @Autowired
    public ValidateClientCertificate(ValidationHelper validationHelper) {
        this.validationHelper = validationHelper;
    }
    /**
     * @param foreignToken - Foreign token which validity is to be confirmed
     * @return Validation status of operation
     */
    public ResponseEntity<ValidationStatus> confirmClientCertificateValidity(@RequestBody String foreignToken) throws MalformedJWTException {

        try {
            ValidationStatus status = validationHelper.validateClientCertificate(foreignToken);

            return ResponseEntity.status(HttpStatus.OK).body(status);
        } catch (Exception e) {
            //TODO return proper information about occuring problem
            return null;
        }
    }
}
