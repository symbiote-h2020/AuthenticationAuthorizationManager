package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes a service that allows users' management.
 *
 * @author Maks Marcinowski (PSNC)
 */
public interface IUserManagement {
    /**
     * @param userManagementRequest required to initialize user's management operation.
     * @return the status of the operation
     */
    @PostMapping(value = SecurityConstants.AAM_MANAGE_USERS, consumes = "application/json")
    ResponseEntity<ManagementStatus> manage(@RequestBody UserManagementRequest userManagementRequest);

    @PostMapping(value = "/getUserDetails", consumes = "application/json")
    UserDetails getUserDetails(@RequestBody Credentials credentials);
}
