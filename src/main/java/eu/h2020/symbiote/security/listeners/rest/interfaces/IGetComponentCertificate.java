package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Interface exposing the SymbIoTe Component's certificate required for challenge response procedure
 *
 * @author Mikołaj Dobski (PSNC)
 */
public interface IGetComponentCertificate {
    /**
     * @return Certificate of the component in PEM format
     */
    @GetMapping(SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE)
    ResponseEntity<String> getComponentCertificate();
}