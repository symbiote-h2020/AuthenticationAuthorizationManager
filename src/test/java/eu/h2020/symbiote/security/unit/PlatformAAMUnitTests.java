package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.TokenManager;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.AAMException;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.token.Token;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @Ignore // todo find a proper way to test RevokedIPK for platform
    @Test
    public void validateRevokedIPK() throws AAMException, CertificateException, SecurityHandlerException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, TimeoutException {

    }

    @Test
    public void validateIssuerDiffersDeploymentIdAndNotInAvailableAAMs() throws AAMException, CertificateException, SecurityHandlerException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException {
        // issuing dummy platform token
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token revoked properly
        CheckRevocationResponse response = tokenManager.validate(dummyHomeToken.getToken());
        assertEquals(ValidationStatus.INVALID, ValidationStatus.valueOf(response.getStatus()));
    }

    //todo tests for relays
    @Test
    public void validateIssuerDiffersDeploymentIdAndInAvailableAAMs() throws AAMException, CertificateException, SecurityHandlerException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException {

    }
}