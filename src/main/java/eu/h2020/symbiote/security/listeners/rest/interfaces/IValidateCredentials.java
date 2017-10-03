package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import org.springframework.http.ResponseEntity;
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
public interface IValidateCredentials {

    /**
     * @param token                                  that is to be validated
     * @param clientCertificate                      in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param clientCertificateSigningAAMCertificate in PEM being the AAM that signed the clientCertificate  in 'offline' (intranet) scenarios
     * @param foreignTokenIssuingAAMCertificate      in PEM with key matching the IPK claim in the provided FOREIGN token in 'offline' (intranet) scenarios
     * @return validation status
     */
    @PostMapping(SecurityConstants.AAM_VALIDATE_CREDENTIALS)
    ValidationStatus validate(
            @RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String token,
            @RequestHeader(name = SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificate,
            @RequestHeader(name = SecurityConstants.AAM_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificateSigningAAMCertificate,
            @RequestHeader(name = SecurityConstants.FOREIGN_TOKEN_ISSUING_AAM_CERTIFICATE, defaultValue = "") String foreignTokenIssuingAAMCertificate);


    /**
     * Allows to confirm that the origin (HOME) credentials (SUB & SPK) used to issue the given FOREIGN token in another AAM have not been revoked and the FOREIGN token should still be deemed valid
     *
     * @param foreignToken - Foreign token which was issued using HOME credentials originating from this AAM
     * @return validation status of the matching HOME credentials which might invalidate the given FOREIGN token
     */
    @PostMapping(SecurityConstants.AAM_VALIDATE_FOREIGN_TOKEN_ORIGIN_CREDENTIALS)
    ResponseEntity<ValidationStatus> validateForeignTokenOriginCredentials(String foreignToken);
}
