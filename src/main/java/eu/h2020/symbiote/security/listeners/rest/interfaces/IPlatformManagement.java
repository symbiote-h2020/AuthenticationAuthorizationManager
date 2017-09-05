package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import io.swagger.annotations.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes a service that allows platforms' management.
 *
 * @author Maks Marcinowski (PSNC)
 */
@Api(value = "/docs/platformmanagement", description = "Exposes a service that allows platforms' management")
public interface IPlatformManagement {
    /**
     * @param platformManagementRequest required to initialize platform's management operation.
     * @return the response containing the status and platform's id
     */
    @ApiOperation(value = "Operation used to manage platform based on contents of management request")
    @PostMapping(value = SecurityConstants.AAM_MANAGE_PLATFORMS, consumes = "application/json")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "AAM Owner Credentials", value = "Credentials used to authorize the request", required = true),
            @ApiImplicitParam(name = "Platform Owner Credentials", value = "Credentials used to register platform owner in database", required = true),
            @ApiImplicitParam(name = "PlatformInterworkingInterfaceAddress", value = "Points Symbiote users to possible login entry points"),
            @ApiImplicitParam(name = "Platform friendly name", value = "Identifies login entry point for users", required = true),
            @ApiImplicitParam(name = "Operation Type", value = "Requested operation", required = true)
    })
    ResponseEntity<PlatformManagementResponse> manage(
            @ApiParam(value = "Platform Management Request", required = true) @RequestBody PlatformManagementRequest platformManagementRequest);

}
