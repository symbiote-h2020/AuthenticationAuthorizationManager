package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IGetClientCertificate;
import eu.h2020.symbiote.security.services.GetClientCertificateService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * @author Maks Marcinowski (PSNC)
 */

@RestController
public class GetClientCertificateController implements IGetClientCertificate {
    private static final Log log = LogFactory.getLog(GetClientCertificateController.class);
    private GetClientCertificateService getClientCertificateService;

    @Autowired
    public GetClientCertificateController(GetClientCertificateService getClientCertificateService) {
        this.getClientCertificateService = getClientCertificateService;
    }

    @Override
    public ResponseEntity<String> getClientCertificate(@RequestBody CertificateRequest certificateRequest) {
        try {
            String certificate = getClientCertificateService.getCertificate(certificateRequest);
            return ResponseEntity.status(HttpStatus.OK).body(certificate);
        } catch (WrongCredentialsException e) {
            return new ResponseEntity<>(e.getErrorMessage(), e.getStatusCode());
        } catch (IOException e) {
            log.error(e);
            // TODO use properly exceptions
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            log.error(e);
            // TODO use properly exceptions
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        } catch (NoSuchProviderException e) {
            log.error(e);
            // TODO use properly exceptions
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        } catch (KeyStoreException e) {
            log.error(e);
            // TODO use properly exceptions
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        } catch (UnrecoverableKeyException e) {
            log.error(e);
            // TODO use properly exceptions
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        } catch (OperatorCreationException e) {
            log.error(e);
            // TODO use properly exceptions
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        } catch (NotExistingUserException e) {
            log.error(e);
            // TODO use properly exceptions
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        } catch (InvalidKeyException e) {
            log.error(e);
            // TODO use properly exceptions
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error(e);
            // TODO use properly exceptions
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        } catch (InvalidArgumentsException e) {
            log.error(e);
            // TODO use properly exceptions
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        } catch (CertificateException e) {
            log.error(e);
            // TODO use properly exceptions
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        }
    }
}
