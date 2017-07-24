package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.SignedObject;

/**
 * Test suite for interactions between multiple AAMs
 */
@TestPropertySource("/core.properties")
@Ignore("Currently contains only R3 tests")
public class CrossAAMFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(CrossAAMFunctionalTests.class);


    /**
     * Feature:
     * Interface: CAAM - 13
     * CommunicationType REST
     */
    @Test
    @Ignore("Not R2, Not yet implemented")
    public void checkRevocationExternalPlatformSuccess() throws IOException {
        SignedObject signObject = CryptoHelper.objectToSignedObject(new String(username + "@" + clientId), userKeyPair.getPrivate());
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants
                        .AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        HttpHeaders loginHeaders = response.getHeaders();
    }

    /**
     * Feature:
     * Interface: CAAM - 13
     * CommunicationType REST
     */
    @Test
    @Ignore("Not R2, Not yet implemented")
    public void checkRevocationExternalPlatformFailure() throws IOException {
        SignedObject signObject = CryptoHelper.objectToSignedObject(new String(username + "@" + clientId), userKeyPair.getPrivate());
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants
                        .AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        HttpHeaders loginHeaders = response.getHeaders();
    }

}