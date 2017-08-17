package eu.h2020.symbiote.security.unit.credentialsvalidation;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

/**
 * Test suite for AAM with expired certificate
 *
 * @author Piotr Kicki (PSNC)
 */
@TestPropertySource("/platformExpired.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class CredentialsValidationInPlatformAAMWithExpiredCertificateUnitTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(CredentialsValidationInPlatformAAMWithExpiredCertificateUnitTests.class);
    @Autowired
    private ValidationHelper validationHelper;

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
    public void validateIssuerCertificateExpired() throws IOException, ValidationException, JWTCreationException {
        // issuing dummy core token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // check if platform token is valid
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.EXPIRED_ISSUER_CERTIFICATE, response);
    }
}