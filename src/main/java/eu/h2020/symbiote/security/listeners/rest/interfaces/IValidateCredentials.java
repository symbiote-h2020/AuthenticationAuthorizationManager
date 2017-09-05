package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Interfaces used to validate tokens and certificates in given AAM
 *
 * @author Piotr Kicki (PSNC)
 * @author Mikołaj Dobski (PSNC)
 * @author Daniele Caldarola (CNIT)
 * @author Pietro Tedeschi (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Api(value = "/docs/validate", description = "Exposes services used to validate tokens and certificates in given AAM")
public interface IValidateCredentials {

    /**
     * @param token                                  that is to be validated
     * @param clientCertificate                      in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param clientCertificateSigningAAMCertificate in PEM being the AAM that signed the clientCertificate  in 'offline' (intranet) scenarios
     * @param foreignTokenIssuingAAMCertificate      in PEM with key matching the IPK claim in the provided FOREIGN token in 'offline' (intranet) scenarios
     * @return validation status
     */
    @ApiOperation(value = "Responds with validation status of processed Validation request", response = ValidationStatus.class)
    @PostMapping(SecurityConstants.AAM_VALIDATE)
    ValidationStatus validate(
            @ApiParam(name = "Token", value = "Token to be validated", required = true) @RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String token,
            @ApiParam(name = "Client Certificate", value = "used for Offline scenarios", required = false) @RequestHeader(name = SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificate,
            @ApiParam(name = "Client Signing Certificate", value = "used for Offline scenarios", required = false) @RequestHeader(name = SecurityConstants.AAM_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificateSigningAAMCertificate,
            @ApiParam(name = "Foreign Token Certificate", value = "used for Offline scenarios", required = false) @RequestHeader(name = SecurityConstants.FOREIGN_TOKEN_ISSUING_AAM_CERTIFICATE, defaultValue = "") String foreignTokenIssuingAAMCertificate);
}
