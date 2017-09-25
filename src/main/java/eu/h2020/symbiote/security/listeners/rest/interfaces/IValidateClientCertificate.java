package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;

/**
 *
 */
public interface IValidateClientCertificate {
    /**
     * @param foreignToken - Foreign token which validity is to be confirmed
     * @return Validation status of operation
     */
    @PostMapping(SecurityConstants.AAM_VALIDATE_CLIENT_CERTIFICATE)
    ResponseEntity<ValidationStatus> confirmClientCertificateValidity(String foreignToken);
}
