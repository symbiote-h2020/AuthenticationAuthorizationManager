package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IManagePlatforms;
import eu.h2020.symbiote.security.services.PlatformsManagementService;
import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to users' management.
 *
 * @author Maks Marcinowski (PSNC)
 * @see PlatformsManagementService
 */
@Profile("core")
@Api(value = "/docs/platformmanagement", description = "Exposes a service that allows platforms' management")
@RestController
public class ManagePlatformsController implements IManagePlatforms {
    private PlatformsManagementService platformsManagementService;

    @Autowired
    public ManagePlatformsController(PlatformsManagementService platformsManagementService) {
        this.platformsManagementService = platformsManagementService;
    }

    @Override
    @ApiOperation(value = "Operation used to manage platform based on contents of management request", response = PlatformManagementResponse.class)
    @ApiResponses({
            @ApiResponse(code = 500, message = "Internal Platform Management Error")})
    public ResponseEntity<PlatformManagementResponse> manage(
            @RequestBody
            @ApiParam(value = "Platform Management Request", required = true)
                    PlatformManagementRequest platformManagementRequest) {
        try {
            PlatformManagementResponse platformManagementResponse = platformsManagementService.authManage(platformManagementRequest);
            return ResponseEntity.status(HttpStatus.OK).body(platformManagementResponse);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new PlatformManagementResponse(null, ManagementStatus.ERROR));
        }
    }
}
