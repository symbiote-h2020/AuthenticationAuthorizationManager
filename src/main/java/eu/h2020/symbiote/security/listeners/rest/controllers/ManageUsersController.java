package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IManageUsers;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.UsersManagementService;
import io.swagger.annotations.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to users' management.
 *
 * @author Maks Marcinowski (PSNC)
 * @see UsersManagementService
 */
@Api(value = "/docs/usermanagement", description = "Exposes a service that allows users' management")
@RestController
public class ManageUsersController implements IManageUsers {
    private static final Log log = LogFactory.getLog(ManageUsersController.class);
    private UsersManagementService usersManagementService;

    @Autowired
    public ManageUsersController(UsersManagementService usersManagementService) {
        this.usersManagementService = usersManagementService;
    }

    @Override
    @ApiOperation(value = "Performs management action based on management request", response = ManagementStatus.class)
    @ApiResponse(code = 500, message = "Internal User Management Error")
    public ResponseEntity<ManagementStatus> manage(
            @RequestBody
            @ApiParam(name = "User Management Request", value = "required to initialize user's management operation", required = true)
                    UserManagementRequest userManagementRequest) {
        try {
            ManagementStatus managementStatus = usersManagementService.authManage(userManagementRequest);
            return ResponseEntity.status(HttpStatus.OK).body(managementStatus);
        } catch (SecurityException e) {
            log.error(e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ManagementStatus.ERROR);
        }
    }

    @Override
    @ApiOperation(value = "Returns details of requested user", response = User.class)
    @ApiResponses({
            @ApiResponse(code = 400, message = "Requested User does not exist"),
            @ApiResponse(code = 401, message = "Incorrect Credentials were provided")})
    public ResponseEntity<UserDetails> getUserDetails(
            @RequestBody
            @ApiParam(name = "Credentials", value = "Credentials of a user whose details are requested", required = true)
                    Credentials credentials) {
        try {
            return new ResponseEntity<>(usersManagementService.getUserDetails(credentials), HttpStatus.OK);
        } catch (UserManagementException e) {
            log.error(e);
            if (e.getStatusCode() == HttpStatus.BAD_REQUEST)
                return new ResponseEntity<>(new UserDetails(), e.getStatusCode());
            else
                return new ResponseEntity<>(new UserDetails(), e.getStatusCode());
        }
    }


}
