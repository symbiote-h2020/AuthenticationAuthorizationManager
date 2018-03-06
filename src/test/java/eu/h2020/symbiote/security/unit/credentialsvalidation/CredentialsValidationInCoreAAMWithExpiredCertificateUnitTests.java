package eu.h2020.symbiote.security.unit.credentialsvalidation;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import static org.junit.Assert.assertEquals;


@TestPropertySource("/core_expired.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class CredentialsValidationInCoreAAMWithExpiredCertificateUnitTests extends AbstractAAMTestSuite {

    @Autowired
    private ValidationHelper validationHelper;
    @Autowired
    private DummyCoreAAM dummyCoreAAM;

    @Test
    public void validateIssuerCertificateExpired() throws
            ValidationException,
            MalformedJWTException {
        // issuing dummy core token from CoreAAM with expired certificate
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyCoreAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        // check if platform token is not revoked
        assertEquals(ValidationStatus.EXPIRED_ISSUER_CERTIFICATE, response);
    }
}
