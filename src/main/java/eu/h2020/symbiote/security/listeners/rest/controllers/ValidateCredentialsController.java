package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IValidateCredentials;
import eu.h2020.symbiote.security.services.CredentialsValidationService;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;


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

    private final ValidationHelper validationHelper;
    private Log log = LogFactory.getLog(ValidateCredentialsController.class);
    private CredentialsValidationService credentialsValidationService;

    @Autowired
    public ValidateCredentialsController(CredentialsValidationService credentialsValidationService,
                                         ValidationHelper validationHelper) {
        this.credentialsValidationService = credentialsValidationService;
        this.validationHelper = validationHelper;
    }

    private String rebuildPEMStringFromHeader(String flatPEMString) {
        String PEMBEGIN = "-----BEGIN CERTIFICATE-----";
        String PEMEND = "-----END CERTIFICATE-----";
        String certificateContent = flatPEMString.substring(PEMBEGIN.length(), flatPEMString.indexOf(PEMEND));
        return PEMBEGIN + '\n' + certificateContent + '\n' + PEMEND;
    }


    @Override
    @ApiOperation(value = "Responds with validation status of processed Validation request", response = ValidationStatus.class)
    public ValidationStatus validate(
            @ApiParam(value = "Token to be validated", required = true)
            @RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String token,
            @ApiParam(value = "used for Offline scenarios")
            @RequestHeader(name = SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificate,
            @ApiParam(value = "used for Offline scenarios")
            @RequestHeader(name = SecurityConstants.AAM_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificateSigningAAMCertificate,
            @ApiParam(value = "used for Offline scenarios")
            @RequestHeader(name = SecurityConstants.FOREIGN_TOKEN_ISSUING_AAM_CERTIFICATE, defaultValue = "") String foreignTokenIssuingAAMCertificate) {
        try {
            // input sanity check
            JWTEngine.validateTokenString(token);

            // rebuilding PEMs from headers
            String parsedClientCert = (clientCertificate.isEmpty()) ? clientCertificate : rebuildPEMStringFromHeader(clientCertificate);
            String parsedClientSigningCert = (clientCertificateSigningAAMCertificate.isEmpty()) ? clientCertificateSigningAAMCertificate : rebuildPEMStringFromHeader(clientCertificateSigningAAMCertificate);
            String parsedForeignTokenCert = (foreignTokenIssuingAAMCertificate.isEmpty()) ? foreignTokenIssuingAAMCertificate : rebuildPEMStringFromHeader(foreignTokenIssuingAAMCertificate);
            // real validation
            return credentialsValidationService.validate(token, parsedClientCert, parsedClientSigningCert, parsedForeignTokenCert);
        } catch (ValidationException | TimeoutException | IOException | WrongCredentialsException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }
    }


    @Override
    public ResponseEntity<ValidationStatus> validateForeignTokenOriginCredentials(@RequestBody String foreignToken) {
        try {
            ValidationStatus status = validationHelper.validateForeignTokenOriginCredentials(foreignToken);
            return ResponseEntity.status(HttpStatus.OK).body(status);
        } catch (CertificateException | MalformedJWTException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ValidationStatus.UNKNOWN);
        }
    }
}
