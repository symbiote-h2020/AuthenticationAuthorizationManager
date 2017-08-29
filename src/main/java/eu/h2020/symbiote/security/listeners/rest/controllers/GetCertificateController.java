package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IGetClientCertificate;
import eu.h2020.symbiote.security.services.GetCertificateService;
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
public class GetCertificateController implements IGetClientCertificate {
    private GetCertificateService getCertificateService;

    @Autowired
    public GetCertificateController(GetCertificateService getCertificateService) {
        this.getCertificateService = getCertificateService;
    }

    @Override
    public ResponseEntity<String> getClientCertificate(@RequestBody CertificateRequest certificateRequest) {
        try {
            String certificate = getCertificateService.getCertificate(certificateRequest);
            return ResponseEntity.status(HttpStatus.OK).body(certificate);
        } catch (WrongCredentialsException | NotExistingUserException | InvalidArgumentsException
                | UserManagementException | PlatformManagementException | ValidationException e) {
            return new ResponseEntity<>(e.getErrorMessage(), e.getStatusCode());
        }
    }
}