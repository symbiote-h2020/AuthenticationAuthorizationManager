package eu.h2020.symbiote.security.unit.credentialsvalidation;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import static org.junit.Assert.assertEquals;


@TestPropertySource("/coreExpired.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class CredentialsValidationInCoreAAMWithExpiredCertificateUnitTests extends AbstractAAMTestSuite {

    @Autowired
    private ValidationHelper validationHelper;

    @Test
    public void validateIssuerCertificateExpired() throws ValidationException {
        // issuing dummy core token from CoreAAM with expired certificate
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/caam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));


        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        // check if platform token is not revoked
        assertEquals(ValidationStatus.EXPIRED_ISSUER_CERTIFICATE, response);
    }
}
