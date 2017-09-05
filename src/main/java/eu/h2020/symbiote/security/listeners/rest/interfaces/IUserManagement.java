package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes a service that allows users' management.
 *
 * @author Maks Marcinowski (PSNC)
 */
@Api(value = "/docs/usermanagement", description = "Exposes a service that allows users' management")
public interface IUserManagement {
    /**
     * @param userManagementRequest required to initialize user's management operation.
     * @return the status of the operation
     */
    @ApiOperation(value = "Performs management action based on management request")
    @PostMapping(value = SecurityConstants.AAM_MANAGE_USERS, consumes = "application/json")
    ResponseEntity<ManagementStatus> manage(
            @ApiParam(name = "User Management Request", value = "required to initialize user's management operation", required = true)
            @RequestBody UserManagementRequest userManagementRequest);

    /**
     * @param credentials of a user whose details are requested
     * @return details concerning requested user. These do NOT contain user's password
     */
    @ApiOperation(value = "Returns details of requested user")
    @PostMapping(value = SecurityConstants.AAM_GET_USER_DETAILS, consumes = "application/json")
    ResponseEntity<UserDetails> getUserDetails(
            @ApiParam(name = "Credentials", value = "Credentials of a user whose details are requested", required = true)
            @RequestBody Credentials credentials);
}
