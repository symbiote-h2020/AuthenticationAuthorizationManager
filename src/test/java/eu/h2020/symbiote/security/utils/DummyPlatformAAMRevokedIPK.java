package eu.h2020.symbiote.security.utils;


import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
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
 * Main purpose of this AAM is to simulate platform with revoked certificate.
 *
 * @author Piotr Kicki (PSNC)
 */
@RestController
public class DummyPlatformAAMRevokedIPK {
    private static final Log log = LogFactory.getLog(DummyPlatformAAMRevokedIPK.class);
    private static final String CERTIFICATE_ALIAS = "platform-1-2-c1";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/platform_1.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private static final String PATH = "/test/rev_ipk/paam";

    public DummyPlatformAAMRevokedIPK() {
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
            Key key = ks.getKey(CERTIFICATE_ALIAS, "1234567".toCharArray());

            HashMap<String, String> attributes = new HashMap<>();
            attributes.put("name", "test2");
            String tokenString = TokenIssuer.buildAuthorizationToken(
                    claims.getIss() + "@" + claims.getSub(),
                    attributes,
                    ks.getCertificate(CERTIFICATE_ALIAS).getPublicKey().getEncoded(),
                    Token.Type.HOME,
                    new Date().getTime() + 60000,
                    "platform-1",
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
     * return valid status
     */
    @PostMapping(path = PATH + SecurityConstants.AAM_VALIDATE)
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
}

