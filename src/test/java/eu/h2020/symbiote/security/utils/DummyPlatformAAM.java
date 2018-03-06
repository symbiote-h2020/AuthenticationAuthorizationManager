package eu.h2020.symbiote.security.utils;

import eu.h2020.symbiote.security.commons.Certificate;
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
import org.springframework.core.io.ClassPathResource;
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
 * @author Mikołaj Dobski (PSNC)
 */
@RestController
public class DummyPlatformAAM {
    private static final Log log = LogFactory.getLog(DummyPlatformAAM.class);
    private static final String PLATFORM_CERTIFICATE_ALIAS = "platform-1-1-c1";
    private static final String P1_CLIENT_CERTIFICATE_CN = "userId@clientId@platform-1";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/keystores/platform_1.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private static final String PATH = "/test/paam";
    public boolean certificateFlag = true;

    public DummyPlatformAAM() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static X509Certificate getCertificateFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), CERTIFICATE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
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
            Key key = ks.getKey(PLATFORM_CERTIFICATE_ALIAS, CERTIFICATE_PASSWORD.toCharArray());

            HashMap<String, String> attributes = new HashMap<>();
            attributes.put("name", "test2");
            String tokenString = TokenIssuer.buildAuthorizationToken(
                    claims.getIss() + "@" + claims.getSub(),
                    attributes,
                    ks.getCertificate(P1_CLIENT_CERTIFICATE_CN).getPublicKey().getEncoded(),
                    Token.Type.HOME, new Date().getTime() + 60000,
                    "platform-1",
                    ks.getCertificate(PLATFORM_CERTIFICATE_ALIAS).getPublicKey(),
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
     * return valid status
     */
    @PostMapping(path = PATH + SecurityConstants.AAM_VALIDATE_CREDENTIALS)
    public ValidationStatus validate(@RequestHeader(SecurityConstants
            .TOKEN_HEADER_NAME) String token) {
        log.info("Validating token " + token);
        return ValidationStatus.VALID;
    }

    /**
     * return valid status of client certificate
     */
    @PostMapping(path = PATH + SecurityConstants.AAM_VALIDATE_FOREIGN_TOKEN_ORIGIN_CREDENTIALS)
    public ValidationStatus validateForeignTokenOriginCredentials(@RequestBody String token) {
        log.info("Dummy Platform AAM validating foreign token origin credentials for: " + token);
        return ValidationStatus.VALID;
    }

    @GetMapping(path = PATH + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE)
    public String getRootCertificate() throws NoSuchProviderException, KeyStoreException, IOException,
            UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(PLATFORM_CERTIFICATE_ALIAS);
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        return signedCertificatePEMDataStringWriter.toString();
    }

    @GetMapping(path = PATH + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE + "/platform/{platformIdentifier}/component/{componentIdentifier}")
    public ResponseEntity<?> getComponentCertificate(String componentIdentifier, String platformIdentifier) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        if (certificateFlag) {
            Certificate cert = new Certificate(
                    CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                            "keystores/core.p12",
                            "registry-core-1")));

            return new ResponseEntity<>(cert.getCertificateString(), HttpStatus.OK);
        } else {
            Certificate cert = new Certificate(
                    CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                            "keystores/core.p12",
                            "rap@platform-1-core-1")));

            return new ResponseEntity<>(cert.getCertificateString(), HttpStatus.OK);
        }
    }
}

