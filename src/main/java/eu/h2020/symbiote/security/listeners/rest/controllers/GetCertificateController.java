package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IGetClientCertificate;
import eu.h2020.symbiote.security.services.GetCertificateService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to certificates issuing.
 *
 * @author Maks Marcinowski (PSNC)
 */

@RestController
@Api(value = "docs/getclientcertificate", description = "Used to receive Client's Certificate")
public class GetCertificateController implements IGetClientCertificate {
    private GetCertificateService getCertificateService;

    @Autowired
    public GetCertificateController(GetCertificateService getCertificateService) {
        this.getCertificateService = getCertificateService;
    }

    @Override
    @ApiOperation(value = "Allows retrieving of Client's Certificate")
    @ApiResponse(code = 500, message = "Could not create Client Certificate")
    public ResponseEntity<String> getClientCertificate(
            @RequestBody
            @ApiParam(value = "Request required to issue a certificate for given (username, clientId) tupple", required = true)
                    CertificateRequest certificateRequest) {
        try {
            String certificate = getCertificateService.getCertificate(certificateRequest);
            return ResponseEntity.status(HttpStatus.OK).body(certificate);
        } catch (WrongCredentialsException | NotExistingUserException | InvalidArgumentsException
                | UserManagementException | PlatformManagementException | ValidationException e) {
            return new ResponseEntity<>(e.getErrorMessage(), e.getStatusCode());
        }
    }
}