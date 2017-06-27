package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.session.AAM;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 *
 * @author Maks Marcinowski (PSNC)
 */
public interface IGetCertificate {
    @PostMapping(value = "/getCertificate")
    ResponseEntity<String> getCertififcate (@RequestBody AAM homeAAM, String username, String password, String clientId, String clientCSR)
            throws WrongCredentialsException, IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
            UnrecoverableKeyException, OperatorCreationException;
}
