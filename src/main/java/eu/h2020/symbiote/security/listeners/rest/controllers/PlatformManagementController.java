package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IPlatformManagement;
import eu.h2020.symbiote.security.services.PlatformsManagementService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to users' management.
 *
 * @author Maks Marcinowski (PSNC)
 * @see PlatformsManagementService
 */

public class PlatformManagementController implements IPlatformManagement {
    private static final Log log = LogFactory.getLog(PlatformManagementController.class);
    private PlatformsManagementService platformsManagementService;

    @Autowired
    public PlatformManagementController(PlatformsManagementService platformsManagementService) {
        this.platformsManagementService = platformsManagementService;
    }

    @Override
    public ResponseEntity<PlatformManagementResponse> manage(@RequestBody PlatformManagementRequest platformManagementRequest) {
        try {
            PlatformManagementResponse platformManagementResponse = platformsManagementService.manage(platformManagementRequest);
            return ResponseEntity.status(HttpStatus.OK).body(platformManagementResponse);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new PlatformManagementResponse(null, ManagementStatus.ERROR));
        }
    }
}
