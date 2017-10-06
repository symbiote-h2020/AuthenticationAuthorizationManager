package eu.h2020.symbiote.security.utils;


import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
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
 *
 * @author Piotr Kicki (PSNC)
 */
@RestController
public class DummyCoreAAM {
    private static final Log log = LogFactory.getLog(DummyCoreAAM.class);
    private static final String CERTIFICATE_ALIAS = "core-2";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/core.p12";
    private static final String PLATFORM_CERTIFICATE_ALIAS = "platform-1-1-c1";
    private static final String PLATFORM_CERTIFICATE_LOCATION = "./src/test/resources/platform_1.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private static final String PATH = "/test/caam";
    private static final String platformId = "platform-1";
    public int port;
    private Certificate revokedCert;
    private AvailableAAMsCollection aams = new AvailableAAMsCollection();

    public DummyCoreAAM() throws
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate("core-1");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        revokedCert = new Certificate(signedCertificatePEMDataStringWriter.toString());
    }

    /**
     * acts temporarily as a core AAM
     */
    @PostMapping(path = PATH + SecurityConstants.AAM_GET_HOME_TOKEN, produces = "application/json", consumes =
            "text/plain")
    public ResponseEntity<?> getHomeToken(@RequestBody String loginRequest) throws
            IOException,
            ClassNotFoundException,
            MalformedJWTException {

        JWTClaims claims = JWTEngine.getClaimsFromToken(loginRequest);
        //log.info("User trying to getHomeToken " + credential.getObject().toString().split("@")[0] + " - " + credential.getObject().toString().split("@")[1]);
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
            Key key = ks.getKey(CERTIFICATE_ALIAS, CERTIFICATE_PASSWORD.toCharArray());

            HashMap<String, String> attributes = new HashMap<>();
            attributes.put("name", "test2");
            String tokenString = TokenIssuer.buildAuthorizationToken(
                    claims.getIss() + "@" + claims.getSub(),
                    attributes,
                    ks.getCertificate(CERTIFICATE_ALIAS).getPublicKey().getEncoded(),
                    Token.Type.HOME,
                    new Date().getTime() + 60000,
                    SecurityConstants.CORE_AAM_INSTANCE_ID,
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

    @PostMapping(path = PATH + SecurityConstants.AAM_VALIDATE_CREDENTIALS)
    public ValidationStatus validate(@RequestHeader(SecurityConstants
            .TOKEN_HEADER_NAME) String token) {
        log.info("Validating token " + token);
        return ValidationStatus.VALID;
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


    @GetMapping(path = PATH + SecurityConstants.AAM_GET_AVAILABLE_AAMS)
    public ResponseEntity<AvailableAAMsCollection> getAvailableAAMs() throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        if (aams.getAvailableAAMs().isEmpty()) {
            initializeAvailableAAMs();
        }
        return new ResponseEntity<>(aams, HttpStatus.OK);
    }

    private void initializeAvailableAAMs() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        aams.getAvailableAAMs().put(SecurityConstants.CORE_AAM_INSTANCE_ID, new AAM("https://localhost:" + port + PATH,
                SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                revokedCert, new HashMap<>()));

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(PLATFORM_CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(PLATFORM_CERTIFICATE_ALIAS);
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        Certificate platformCert = new Certificate(signedCertificatePEMDataStringWriter.toString());

        aams.getAvailableAAMs().put(platformId, new AAM("https://localhost:" + port,
                SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                platformId,
                platformCert, new HashMap<>()));
    }
}

