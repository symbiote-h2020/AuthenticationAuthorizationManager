package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.repositories.entities.User;
import io.swagger.annotations.*;
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
    @ApiOperation(value = "Performs management action based on management request", response = ManagementStatus.class)
    @ApiResponse(code = 500, message = "Internal User Management Error")
    @PostMapping(value = SecurityConstants.AAM_MANAGE_USERS, consumes = "application/json")
    ResponseEntity<ManagementStatus> manage(
            @ApiParam(name = "User Management Request", value = "required to initialize user's management operation", required = true)
            @RequestBody UserManagementRequest userManagementRequest);

    /**
     * @param credentials of a user whose details are requested
     * @return details concerning requested user. These do NOT contain user's password
     */
    @ApiOperation(value = "Returns details of requested user", response = User.class)
    @ApiResponses({
            @ApiResponse(code = 400, message = "Requested User does not exist"),
            @ApiResponse(code = 401, message = "Incorrect Credentials were provided")})
    @PostMapping(value = SecurityConstants.AAM_GET_USER_DETAILS, consumes = "application/json")
    ResponseEntity<UserDetails> getUserDetails(
            @ApiParam(name = "Credentials", value = "Credentials of a user whose details are requested", required = true)
            @RequestBody Credentials credentials);
}
