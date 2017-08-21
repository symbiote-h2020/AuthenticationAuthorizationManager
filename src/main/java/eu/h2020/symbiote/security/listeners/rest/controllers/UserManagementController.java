package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IUserManagement;
import eu.h2020.symbiote.security.services.UsersManagementService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Maks Marcinowski (PSNC)
 */

@RestController
public class UserManagementController implements IUserManagement {
    private static final Log log = LogFactory.getLog(UserManagementController.class);
    private UsersManagementService usersManagementService;

    @Autowired
    public UserManagementController(UsersManagementService usersManagementService) {
        this.usersManagementService = usersManagementService;
    }

    @Override
    public ResponseEntity<ManagementStatus> manage(@RequestBody UserManagementRequest userManagementRequest) {
        try {
            ManagementStatus managementStatus = usersManagementService.manage(userManagementRequest);
            return ResponseEntity.status(HttpStatus.OK).body(managementStatus);
        } catch (SecurityException e) {
            log.error(e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ManagementStatus.ERROR);
        }
    }

}
