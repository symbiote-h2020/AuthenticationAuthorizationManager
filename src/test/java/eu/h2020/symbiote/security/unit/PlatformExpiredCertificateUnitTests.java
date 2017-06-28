package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.TokenManager;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertEquals;

/**
 * Test suite for AAM with expired certificate
 *
 * @author Piotr Kicki (PSNC)
 */
@TestPropertySource("/platformExpired.properties")
public class PlatformExpiredCertificateUnitTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(PlatformExpiredCertificateUnitTests.class);
    @Autowired
    private TokenManager tokenManager;

    @Bean
    DummyPlatformAAM getDummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @Test
    public void validateIssuerCertificateExpired() throws IOException, TimeoutException,
            NoSuchProviderException, KeyStoreException, CertificateException,
            NoSuchAlgorithmException, ValidationException, JWTCreationException {
        // issuing dummy core token
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

        ValidationStatus response = tokenManager.validate(dummyHomeToken.getToken(), "");
        // check if platform token is not revoked
        assertEquals(ValidationStatus.EXPIRED_ISSUER_CERTIFICATE, response);
    }
}