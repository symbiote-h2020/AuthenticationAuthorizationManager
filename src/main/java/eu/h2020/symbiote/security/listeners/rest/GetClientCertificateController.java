package eu.h2020.symbiote.security.listeners.rest;

import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.interfaces.IGetClientCertificate;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;
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
        try{
            // TODO review that the CSR is in PEM format...
            String certificate = getClientCertificateService.getCertificate(certificateRequest);
            return ResponseEntity.status(HttpStatus.OK).body(certificate);
        }catch(WrongCredentialsException | IOException | CertificateException | NoSuchAlgorithmException |
                NoSuchProviderException | KeyStoreException | UnrecoverableKeyException | OperatorCreationException |
                NotExistingUserException | InvalidKeyException | IllegalArgumentException e){
            log.error(e);
            return ResponseEntity.status(HttpStatus.OK).body(e.getMessage());
        }
    }
}
