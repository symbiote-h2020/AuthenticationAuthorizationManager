package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.rest.CertificateRequest;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Access to service offered by CertificateService
 * @author Maks Marcinowski (PSNC)
 */
public interface IGetCertificate {
    @PostMapping(value = AAMConstants.AAM_PUBLIC_PATH + "/certificate")
    ResponseEntity<String> getCertificate(@RequestBody CertificateRequest certificateRequest)
            throws WrongCredentialsException, IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
            UnrecoverableKeyException, OperatorCreationException, NotExistingUserException, InvalidKeyException;
}
