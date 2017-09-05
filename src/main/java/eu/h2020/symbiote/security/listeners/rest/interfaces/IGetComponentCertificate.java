package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Interface exposing the SymbIoTe Component's certificate required for challenge response procedure
 *
 * @author Mikołaj Dobski (PSNC)
 */
@Api(value = "/docs/getcomponentcertificate", description = "Exposes service used to receive Component Certificate")
public interface IGetComponentCertificate {
    /**
     * @return Certificate of the component in PEM format
     */
    @ApiOperation(value = "Returns Component Certificate", response = String.class)
    @ApiResponse(code = 500, message = "Could not create Component Certificate")
    @GetMapping(SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE)
    ResponseEntity<String> getComponentCertificate();
}