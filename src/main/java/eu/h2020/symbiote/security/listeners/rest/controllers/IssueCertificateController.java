package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IIssueCertificate;
import eu.h2020.symbiote.security.services.IssueCertificateService;
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
@Api(value = "docs/issueCertificate", description = "Used to issue symbiote certificates")
public class IssueCertificateController implements IIssueCertificate {
    private IssueCertificateService issueCertificateService;

    @Autowired
    public IssueCertificateController(IssueCertificateService issueCertificateService) {
        this.issueCertificateService = issueCertificateService;
    }

    @Override
    @ApiOperation(value = "Allows issuing user's Certificates")
    @ApiResponses({
            @ApiResponse(code = 500, message = "Could not issue the requested certificate")})
    public ResponseEntity<String> issueCertificate(
            @RequestBody
            @ApiParam(value = "Request required to issue a certificate for given (username, clientId) tupple", required = true)
                    CertificateRequest certificateRequest) {
        try {
            String certificate = issueCertificateService.issueCertificate(certificateRequest);
            return ResponseEntity.status(HttpStatus.OK).body(certificate);
        } catch (WrongCredentialsException | NotExistingUserException | InvalidArgumentsException
                | UserManagementException | ServiceManagementException | ValidationException e) {
            return new ResponseEntity<>(e.getErrorMessage(), e.getStatusCode());
        } catch (CertificateException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}