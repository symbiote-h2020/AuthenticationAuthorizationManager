package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.constants.SecurityConstants;
import eu.h2020.symbiote.security.payloads.Credentials;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

/**
 * Test suite for interactions between multiple AAMs
 */
@TestPropertySource("/core.properties")
@Ignore("Currently contains only R3 tests")
public class CrossAAMIntegrationTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(CrossAAMIntegrationTests.class);


    /**
     * Feature:
     * Interface: CAAM - 13
     * CommunicationType REST
     */
    @Test
    @Ignore("Not R2, Not yet implemented")
    public void checkRevocationExternalPlatformSuccess() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants
                        .AAM_GET_HOME_TOKEN,
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();
    }

    /**
     * Feature:
     * Interface: CAAM - 13
     * CommunicationType REST
     */
    @Test
    @Ignore("Not R2, Not yet implemented")
    public void checkRevocationExternalPlatformFailure() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants
                        .AAM_GET_HOME_TOKEN,
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();
    }

}