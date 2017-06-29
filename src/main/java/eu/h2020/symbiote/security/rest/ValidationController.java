package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.interfaces.IValidation;
import eu.h2020.symbiote.security.services.ValidationService;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to token validation in Cloud
 * AAM component.
 *
 * @author Piotr Kicki (PSNC)
 * @see ValidationService
 */
@RestController
public class ValidationController implements IValidation {

    private Log log = LogFactory.getLog(ValidationController.class);
    private ValidationService validationService;

    @Value("${symbiote.coreaam.url:localhost}")
    private String coreAAMAddress = "";

    @Autowired
    public ValidationController(ValidationService validationService) {
        this.validationService = validationService;
    }


    @Override
    public ValidationStatus validate(@RequestHeader(AAMConstants.TOKEN_HEADER_NAME) String tokenString,
                                     @RequestHeader(name = AAMConstants.CERTIFICATE_HEADER_NAME, defaultValue = "")
                                             String certificateString) {
        try {
            // input sanity check
            JWTEngine.validateTokenString(tokenString);
            // real validation
            return validationService.validate(tokenString, certificateString);
        } catch (ValidationException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }
    }
}
