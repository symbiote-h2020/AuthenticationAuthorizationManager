package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

public interface IUserManagement {
    /**
     * Exposes a service that allows users' management.
     *
     * @param userManagementRequest required to initial.
     * @return the certificate issued using the provided CSR in PEM format
     */
    @PostMapping(value = SecurityConstants.AAM_MANAGE, consumes = "application/json")
    ResponseEntity<ManagementStatus> manage(@RequestBody UserManagementRequest userManagementRequest);
}
