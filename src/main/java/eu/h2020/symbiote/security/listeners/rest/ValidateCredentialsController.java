package eu.h2020.symbiote.security.listeners.rest;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.interfaces.IValidateCredentials;
import eu.h2020.symbiote.security.services.CredentialsValidationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.HeaderParam;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to token validation in
 * Cloud
 * AAM component.
 *
 * @author Piotr Kicki (PSNC)
 * @see CredentialsValidationService
 */
@RestController
public class ValidateCredentialsController implements IValidateCredentials {

    private Log log = LogFactory.getLog(ValidateCredentialsController.class);
    private CredentialsValidationService credentialsValidationService;

    @Value("${symbiote.coreaam.url:localhost}")
    private String coreAAMAddress = "";

    @Autowired
    public ValidateCredentialsController(CredentialsValidationService credentialsValidationService) {
        this.credentialsValidationService = credentialsValidationService;
    }

    @Override
    public ValidationStatus validate(@HeaderParam(SecurityConstants.TOKEN_HEADER_NAME) String token,
                                     @HeaderParam(SecurityConstants.CERTIFICATE_HEADER_NAME) @DefaultValue("")
                                             String certificate) {
        try {
            // input sanity check
            JWTEngine.validateTokenString(token);
            // real validation
            return credentialsValidationService.validate(token, certificate);
        } catch (ValidationException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }
    }
}
