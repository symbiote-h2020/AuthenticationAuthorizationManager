package eu.h2020.symbiote.security.utils;


import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;


/**
 * Dummy REST service mimicking exposed AAM features required by SymbIoTe users and reachable via CoreInterface in
 * the Core and Interworking Interfaces on Platforms' side.
 *
 * @author Piotr Kicki (PSNC)
 */
@RestController
public class DummyPlatformAAMConnectionProblem {
    private static final Log log = LogFactory.getLog(DummyPlatformAAMConnectionProblem.class);
    private static final String CERTIFICATE_ALIAS = "platform-1-1-c1";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/platform_1.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private static final String PATH = "/test/conn_err/paam";

    public DummyPlatformAAMConnectionProblem() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * acts temporarily as a platform AAM
     */
    @RequestMapping(method = RequestMethod.POST, path = PATH + AAMConstants.AAM_LOGIN, produces =
            "application/json", consumes = "application/json")
    public ResponseEntity<?> doLogin(@RequestBody Credentials credential) {
        log.info("User trying to login " + credential.getUsername() + " - " + credential.getPassword());
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
            Key key = ks.getKey(CERTIFICATE_ALIAS, CERTIFICATE_PASSWORD.toCharArray());

            HashMap<String, String> attributes = new HashMap<>();
            attributes.put("name", "test2");
            String tokenString = JWTEngine.generateJWTToken(credential.getUsername(), attributes, ks.getCertificate
                            (CERTIFICATE_ALIAS).getPublicKey().getEncoded(), IssuingAuthorityType.PLATFORM, new Date().getTime()
                            + 60000
                    , "testaam-connerr", ks.getCertificate(CERTIFICATE_ALIAS).getPublicKey(),
                    (PrivateKey) key);

            Token coreToken = new Token(tokenString);

            HttpHeaders headers = new HttpHeaders();
            headers.add(AAMConstants.TOKEN_HEADER_NAME, coreToken.getToken());

            /* Finally issues and return foreign_token */
            return new ResponseEntity<>(headers, HttpStatus.OK);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException |
                UnrecoverableKeyException | JWTCreationException | NoSuchProviderException | ValidationException
                e) {
            log.error(e);
        }
        return null;
    }

    /**
     * return invalid status
     */
    @RequestMapping(method = RequestMethod.POST, path = PATH + AAMConstants.AAM_CHECK_HOME_TOKEN_REVOCATION)
    public ResponseEntity<CheckRevocationResponse> checkTokenRevocation(@RequestHeader(AAMConstants
            .TOKEN_HEADER_NAME) String token) {
        log.info("Checking token revocation " + token);
        return new ResponseEntity<>(new CheckRevocationResponse
                (ValidationStatus.NULL), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @RequestMapping(method = RequestMethod.GET, path = PATH + AAMConstants.AAM_GET_CA_CERTIFICATE)
    public String getRootCertificate() throws NoSuchProviderException, KeyStoreException, IOException,
            UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(CERTIFICATE_ALIAS);
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        return signedCertificatePEMDataStringWriter.toString();
    }
}

