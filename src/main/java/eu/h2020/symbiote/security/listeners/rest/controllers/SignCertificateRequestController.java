package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.ISignCertificateRequest;
import eu.h2020.symbiote.security.services.SignCertificateRequestService;
import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.CertificateException;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to certificates signing.
 *
 * @author Maks Marcinowski (PSNC)
 * @author Jakub Toczek (PSNC)
 */

@RestController
@Api(value = "docs/signCertificateRequest", description = "Used to sign symbiote certificates")
public class SignCertificateRequestController implements ISignCertificateRequest {
    private SignCertificateRequestService signCertificateRequestService;

    @Autowired
    public SignCertificateRequestController(SignCertificateRequestService signCertificateRequestService) {
        this.signCertificateRequestService = signCertificateRequestService;
    }

    @Override
    @ApiOperation(value = "Allows signing certificates' requests")
    @ApiResponses({
            @ApiResponse(code = 403, message = "Client account is not activated or blocked"),
            @ApiResponse(code = 500, message = "Could not sign the requested certificate")})
    public ResponseEntity<String> signCertificateRequest(
            @RequestBody
            @ApiParam(value = "Request required to sign a certificate for given (username, clientId) tupple", required = true)
                    CertificateRequest certificateRequest) {
        try {
            String certificate = signCertificateRequestService.signCertificateRequest(certificateRequest);
            return ResponseEntity.status(HttpStatus.OK).body(certificate);
        } catch (WrongCredentialsException | NotExistingUserException | InvalidArgumentsException
                | UserManagementException | ServiceManagementException | ValidationException e) {
            return new ResponseEntity<>(e.getErrorMessage(), e.getStatusCode());
        } catch (CertificateException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}