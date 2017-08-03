package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Interfaces used to validate tokens and certificates in given AAM
 *
 * @author Piotr Kicki (PSNC)
 */
public interface IValidateCredentials {

    /**
     * @param token       that is to be validated
     * @param certificate matching the SPK from the token
     * @return validation status
     */
    @PostMapping(SecurityConstants.AAM_VALIDATE)
    ValidationStatus validate(@RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String token,
                              @RequestHeader(name = SecurityConstants.CERTIFICATE_HEADER_NAME,
                                      defaultValue = "") String certificate);
}
