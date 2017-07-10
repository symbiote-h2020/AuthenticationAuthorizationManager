package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.commons.TokenManager;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.utils.DummyPlatformAAMRevokedIPK;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import static org.mockito.Mockito.*;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for generic AAM functionality - deployment type Platform
 *
 * @author Piotr Kicki (PSNC)
 */
@TestPropertySource("/platform.properties")
public class PlatformAAMUnitTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(PlatformAAMUnitTests.class);
    @Autowired
    private TokenManager tokenManager;

/*
    @Bean
    DummyPlatformAAMRevokedIPK getDummyPlatformAAMRevokedIPK() {
        return new DummyPlatformAAMRevokedIPK();
    }
*/
    @MockBean
    DummyPlatformAAMRevokedIPK dummyRevoked;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        //  Defining Mocked Class Behaviour
        ResponseEntity d_Response = dummyRevoked.substituteDoLogin(new Credentials(username,password));
        when(dummyRevoked.doLogin(any(Credentials.class))).thenReturn(d_Response);
        when(dummyRevoked.validate(anyString())).thenReturn(ValidationStatus.VALID);
        when(dummyRevoked.getRootCertificate()).thenCallRealMethod();
    }

    @Test
    public void validateValidPlatform() throws SecurityException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, TimeoutException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenManager.createHomeToken(user);

        // check if home token is valid
        ValidationStatus response = tokenManager.validate(homeToken.getToken(), "");
        assertEquals(ValidationStatus.VALID, response);
    }

    @Test
    public void validateRevokedIPK() throws SecurityException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, TimeoutException {
        // issuing dummy platform token from platform with revoked certificate
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/rev_ipk/paam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token is valid
        ValidationStatus response = tokenManager.validate(dummyHomeToken.getToken(), "");
        assertEquals(ValidationStatus.REVOKED_IPK, response);
    }

    @Test
    public void validateIssuerDiffersDeploymentIdAndNotInAvailableAAMs() throws SecurityException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException {
        // issuing dummy platform token from unregistered platform
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/second/paam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token is valid
        ValidationStatus response = tokenManager.validate(dummyHomeToken.getToken(), "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateExpiredSubjectCertificate() throws SecurityException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, TimeoutException, InvalidAlgorithmParameterException, UnrecoverableKeyException, OperatorCreationException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenManager.createHomeToken(user);

        // injection of expired certificate
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/platform_1.p12"), "1234567".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate("platform-1-1-exp-c1");
        Certificate certificate = new Certificate(registrationManager.convertX509ToPEM(cert));
        user.setCertificate(certificate);
        userRepository.save(user);

        // check if home token is valid
        ValidationStatus response = tokenManager.validate(homeToken.getToken(), "");
        assertEquals(ValidationStatus.EXPIRED_SUBJECT_CERTIFICATE, response);
    }

    @Test
    public void validateIssuerDiffersDeploymentIdAndInAvailableAAMsButRevoked() throws SecurityException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException {
        // issuing dummy platform token
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/caam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token is valid
        ValidationStatus response = tokenManager.validate(dummyHomeToken.getToken(), "");
        assertEquals(ValidationStatus.REVOKED_IPK, response);
    }
}