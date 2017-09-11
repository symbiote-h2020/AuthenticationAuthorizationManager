package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IValidateCredentials;
import eu.h2020.symbiote.security.services.CredentialsValidationService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
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
@Api(value = "/docs/validateCredentials", description = "Exposes services used to validate tokens and certificates in given AAM")
public class ValidateCredentialsController implements IValidateCredentials {

    private Log log = LogFactory.getLog(ValidateCredentialsController.class);
    private CredentialsValidationService credentialsValidationService;

    @Autowired
    public ValidateCredentialsController(CredentialsValidationService credentialsValidationService) {
        this.credentialsValidationService = credentialsValidationService;
    }

    @Override
    @ApiOperation(value = "Responds with validation status of processed Validation request", response = ValidationStatus.class)
    public ValidationStatus validate(
            @ApiParam(value = "Token to be validated", required = true)
            @RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String token,
            @ApiParam(value = "used for Offline scenarios", required = false)
            @RequestHeader(name = SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificate,
            @ApiParam(value = "used for Offline scenarios", required = false)
            @RequestHeader(name = SecurityConstants.AAM_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificateSigningAAMCertificate,
            @ApiParam(value = "used for Offline scenarios", required = false)
            @RequestHeader(name = SecurityConstants.FOREIGN_TOKEN_ISSUING_AAM_CERTIFICATE, defaultValue = "") String foreignTokenIssuingAAMCertificate) {
        try {
            // input sanity check
            JWTEngine.validateTokenString(token);
            // real validation
            return credentialsValidationService.validate(token, clientCertificate, clientCertificateSigningAAMCertificate, foreignTokenIssuingAAMCertificate);
        } catch (ValidationException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }
    }
}
