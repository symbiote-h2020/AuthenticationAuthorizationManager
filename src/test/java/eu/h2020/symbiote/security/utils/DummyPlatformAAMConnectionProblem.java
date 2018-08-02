package eu.h2020.symbiote.security.utils;


import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
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
 * Main purpose of this AAM is to simulate problems with connection during validation.
 *
 * @author Piotr Kicki (PSNC)
 */
@RestController
public class DummyPlatformAAMConnectionProblem {
    private static final Log log = LogFactory.getLog(DummyPlatformAAMConnectionProblem.class);
    private static final String CERTIFICATE_ALIAS = "platform-1-1-c1";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/keystores/platform_1.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private static final String PATH = "/test/conn_err/aam";
    // Leaf Certificate
    private static String applicationCertificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIB6jCCAZCgAwIBAgIEWWyv1DAKBggqhkjOPQQDAjB0MRQwEgYJKoZIhvcNAQkB\n" +
                    "FgVhQGIuYzENMAsGA1UECxMEdGVzdDENMAsGA1UEChMEdGVzdDENMAsGA1UEBxME\n" +
                    "dGVzdDENMAsGA1UECBMEdGVzdDELMAkGA1UEBhMCUEwxEzARBgNVBAMTCnBsYXRm\n" +
                    "b3JtLTEwHhcNMTcwNzE3MTIzODUxWhcNMTgwNzE3MTIzODUxWjCBhTEUMBIGCSqG\n" +
                    "SIb3DQEJARYFYUBiLmMxCzAJBgNVBAYTAklUMQ0wCwYDVQQIDAR0ZXN0MQ0wCwYD\n" +
                    "VQQHDAR0ZXN0MQ0wCwYDVQQKDAR0ZXN0MQ0wCwYDVQQLDAR0ZXN0MSQwIgYDVQQD\n" +
                    "DBthcHBsaWNhdGlvbi1wbGF0Zm9ybS0xLTEtYzEwWTATBgcqhkjOPQIBBggqhkjO\n" +
                    "PQMBBwNCAASGxfZa6ivSR4+BWBHRh94MNURAXBpBrZECvMH/rcgm8/aTHach6ncN\n" +
                    "fw8VY2RNf3l/runJOQQH/3xGEisDIY7fMAoGCCqGSM49BAMCA0gAMEUCIDrJxAet\n" +
                    "0IqR6aiJc87BS1faA8Ijl7kQnkphPOazKiXXAiEAoVHhBTNZACa4+2/0OsSg2k2P\n" +
                    "jExF7CXu6SB/rvivAXk=\n" +
                    "-----END CERTIFICATE-----\n";

    public DummyPlatformAAMConnectionProblem() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * acts temporarily as a platform AAM
     */
    @PostMapping(path = PATH + SecurityConstants.AAM_GET_HOME_TOKEN, produces = "application/json", consumes =
            "text/plain")
    public ResponseEntity<?> getHomeToken(@RequestBody String loginRequest) throws
            IOException,
            ClassNotFoundException,
            MalformedJWTException {
        JWTClaims claims = JWTEngine.getClaimsFromToken(loginRequest);
        log.info("User trying to getHomeToken " + claims.getIss() + " - " + claims.getSub());
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
            Key key = ks.getKey(CERTIFICATE_ALIAS, CERTIFICATE_PASSWORD.toCharArray());

            HashMap<String, String> attributes = new HashMap<>();
            attributes.put("name", "test2");
            String tokenString = TokenIssuer.buildAuthorizationToken(
                    claims.getIss() + "@" + claims.getSub(),
                    attributes,
                    CryptoHelper.convertPEMToX509(applicationCertificatePEM).getPublicKey().getEncoded(),
                    Token.Type.HOME,
                    new Date().getTime() + 60000,
                    "testaam-connerr",
                    ks.getCertificate(CERTIFICATE_ALIAS).getPublicKey(),
                    (PrivateKey) key);

            Token coreToken = new Token(tokenString);

            HttpHeaders headers = new HttpHeaders();
            headers.add(SecurityConstants.TOKEN_HEADER_NAME, coreToken.getToken());

            /* Finally issues and return foreign_token */
            return new ResponseEntity<>(headers, HttpStatus.OK);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException |
                UnrecoverableKeyException | NoSuchProviderException | ValidationException
                e) {
            log.error(e);
        }
        return null;
    }

    /**
     * return invalid status
     */
    @PostMapping(path = PATH + SecurityConstants.AAM_VALIDATE_CREDENTIALS + "conn_err")
    public ValidationStatus validate(@RequestHeader(SecurityConstants
            .TOKEN_HEADER_NAME) String token) {
        log.info("Validating token " + token);
        return null;
    }

    @GetMapping(path = PATH + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE)
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

