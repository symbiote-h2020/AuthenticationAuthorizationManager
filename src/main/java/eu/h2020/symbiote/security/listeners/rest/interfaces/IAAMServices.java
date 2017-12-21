package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Access to other services that AAMs offer.
 *
 * @author Piotr Kicki (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IAAMServices {

    /**
     * @return collection of AAMs available in the SymbIoTe ecosystem
     */
    @GetMapping(value = SecurityConstants.AAM_GET_AVAILABLE_AAMS,
            produces = "application/json")
    ResponseEntity<AvailableAAMsCollection> getAvailableAAMs();

    /**
     * @return collection of AAMs in the SymbIoTe ecosystem
     */
    @GetMapping(value = SecurityConstants.AAM_GET_AAMS_INTERNALLY,
            produces = "application/json")
    ResponseEntity<AvailableAAMsCollection> getAAMsInternally();
}
