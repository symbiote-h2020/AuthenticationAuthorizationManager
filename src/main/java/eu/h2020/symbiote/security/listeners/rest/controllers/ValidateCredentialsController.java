package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IValidateCredentials;
import eu.h2020.symbiote.security.services.CredentialsValidationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to credentials validation.
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Piotr Kicki (PSNC)
 * @see CredentialsValidationService
 */
@RestController
public class ValidateCredentialsController implements IValidateCredentials {

    private Log log = LogFactory.getLog(ValidateCredentialsController.class);
    private CredentialsValidationService credentialsValidationService;

    @Autowired
    public ValidateCredentialsController(CredentialsValidationService credentialsValidationService) {
        this.credentialsValidationService = credentialsValidationService;
    }

    @Override
    public ValidationStatus validate(@RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String token,
                                     @RequestHeader(name = SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificate,
                                     @RequestHeader(name = SecurityConstants.AAM_CERTIFICATE_HEADER_NAME, defaultValue = "") String aamCertificate) {
        try {
            // input sanity check
            JWTEngine.validateTokenString(token);
            // real validation
            // todo handle the aamCertificate
            return credentialsValidationService.validate(token, clientCertificate);
        } catch (ValidationException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }
    }
}
