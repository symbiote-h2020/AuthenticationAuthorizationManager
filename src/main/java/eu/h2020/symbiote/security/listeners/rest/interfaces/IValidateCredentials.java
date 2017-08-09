package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
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
     * @param token             that is to be validated
     * @param clientCertificate in PEM with key matching the SPK claim in the provided token in 'offline' (intranet) scenarios
     * @param aamCertificate    in PEM with key matching the IPK claim in the provided token in 'offline' (intranet) scenarios
     * @return validation status
     */
    @PostMapping(SecurityConstants.AAM_VALIDATE)
    ValidationStatus validate(@RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String token,
                              @RequestHeader(name = SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME, defaultValue = "") String clientCertificate,
                              @RequestHeader(name = SecurityConstants.AAM_CERTIFICATE_HEADER_NAME, defaultValue = "") String aamCertificate);
}
