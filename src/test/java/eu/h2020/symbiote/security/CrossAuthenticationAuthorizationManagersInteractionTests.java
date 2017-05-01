package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.commons.json.Credentials;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * Test suite for interactions between multiple AAMs
 */
@TestPropertySource("/core.properties")
@Ignore("Currently contains only R3 tests")
public class CrossAuthenticationAuthorizationManagersInteractionTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CrossAuthenticationAuthorizationManagersInteractionTests.class);


    /**
     * Feature:
     * Interface: CAAM - 13
     * CommunicationType REST
     */
    @Test
    @Ignore("Not R2, Not yet implemented")
    public void checkRevocationExternalPlatformSuccess() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
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
        try {
            ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                    new Credentials(username, password), String.class);
            HttpHeaders loginHeaders = response.getHeaders();


        } catch (Exception e) {

        }
    }

}