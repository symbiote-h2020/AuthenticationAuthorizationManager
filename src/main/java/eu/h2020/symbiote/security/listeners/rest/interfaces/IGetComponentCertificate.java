package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * Interface exposing the SymbIoTe component's certificate required for challenge response procedure
 *
 * @author Mikołaj Dobski (PSNC)
 */
public interface IGetComponentCertificate {
    /**
     * @param componentIdentifier component identifier or {@link SecurityConstants#AAM_COMPONENT_NAME} for AAM CA certificate
     * @param platformIdentifier  for a platform component or {@link SecurityConstants#CORE_AAM_INSTANCE_ID} for Symbiote core components
     * @return symbiote component Certificate of the component in PEM format
     */
    @GetMapping(SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE + "/platform/{platformIdentifier}/component/{componentIdentifier}")
    ResponseEntity<String> getComponentCertificate(@PathVariable String componentIdentifier,
                                                   @PathVariable String platformIdentifier);
}