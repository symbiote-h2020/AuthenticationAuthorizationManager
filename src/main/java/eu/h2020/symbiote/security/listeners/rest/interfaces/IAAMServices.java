package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Access to other services that AAMs offer.
 *
 * @author Piotr Kicki (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Api(value = "/docs/aamservices", description = "Exposes services provided by AAM", produces = "application/json")
public interface IAAMServices {

    /**
     * @return collection of AAMs available in the SymbIoTe ecosystem
     */
    @ApiOperation(value = "Returns collection of available AAMs", response = AvailableAAMsCollection.class)
    @ApiResponses(value = {@ApiResponse(code = 200, message = "OK"),
            @ApiResponse(code = 500, message = "Internal AAM Error")})
    @GetMapping(value = SecurityConstants.AAM_GET_AVAILABLE_AAMS, produces =
            "application/json")
    ResponseEntity<AvailableAAMsCollection> getAvailableAAMs();
}
