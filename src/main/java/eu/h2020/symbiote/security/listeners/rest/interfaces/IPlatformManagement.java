package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
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
    @ApiOperation(value = "Operation used to manage platform based on contents of management request", response = PlatformManagementResponse.class)
    @ApiResponse(code = 500, message = "Internal Platform Management Error")
    @PostMapping(value = SecurityConstants.AAM_MANAGE_PLATFORMS, consumes = "application/json")
    ResponseEntity<PlatformManagementResponse> manage(
            @ApiParam(value = "Platform Management Request", required = true) @RequestBody PlatformManagementRequest platformManagementRequest);

}
