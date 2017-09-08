package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes a service that allows platforms' management.
 *
 * @author Maks Marcinowski (PSNC)
 */
public interface IManagePlatforms {
    /**
     * @param platformManagementRequest required to initialize platform's management operation.
     * @return the response containing the status and platform's id
     */
    @PostMapping(value = SecurityConstants.AAM_MANAGE_PLATFORMS, consumes = "application/json")
    ResponseEntity<PlatformManagementResponse> manage(@RequestBody PlatformManagementRequest platformManagementRequest);

}
