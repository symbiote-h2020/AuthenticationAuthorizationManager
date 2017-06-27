package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.interfaces.IGetCertificate;
import eu.h2020.symbiote.security.services.CertificateService;
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
public class CertificateController implements IGetCertificate {
    private static final Log log = LogFactory.getLog(CertificateController.class);
    private CertificateService certificateService;

    @Autowired
    public CertificateController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Override
    public ResponseEntity<String> getCertififcate(@RequestBody CertificateRequest certificateRequest) throws WrongCredentialsException, IOException, CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, UnrecoverableKeyException, OperatorCreationException, NotExistingUserException, InvalidKeyException {
        try{
            String certificate = certificateService.getCertificate(certificateRequest);
            return ResponseEntity.status(HttpStatus.OK).body(certificate);
        }catch(Exception e){
            log.debug(e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }
}
