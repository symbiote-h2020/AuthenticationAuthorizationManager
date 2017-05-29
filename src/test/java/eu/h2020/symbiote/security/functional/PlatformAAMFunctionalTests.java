package eu.h2020.symbiote.security.functional;

import com.fasterxml.jackson.core.JsonProcessingException;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.payloads.UserDetails;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import eu.h2020.symbiote.security.payloads.UserRegistrationResponse;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for Platform side AAM deployment scenarios.
 */
@TestPropertySource("/platform.properties")
public class PlatformAAMFunctionalTests extends
        AbstractAAMTestSuite {

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    /**
     * Feature: PAAM - 2 (Application Registration)
     * Interface: PAAM - 3a
     * CommunicationType REST
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationRegistrationOverRESTSuccess() throws JsonProcessingException {
        String testAppUsername = "NewApplication";
        UserRegistrationRequest request = new UserRegistrationRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new UserDetails(new Credentials(testAppUsername, "NewPassword"), "", "", UserRole.APPLICATION));
        // verify that app is not in the repository
        User registeredUser = userRepository.findOne(testAppUsername);
        assertNull(registeredUser);

        ResponseEntity<UserRegistrationResponse> response = restTemplate.postForEntity(serverAddress +
                registrationUri, request, UserRegistrationResponse.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        // verify that app really is in repository
        registeredUser = userRepository.findOne(testAppUsername);
        assertNotNull(registeredUser);
        assertEquals(UserRole.APPLICATION, registeredUser.getRole());

        // verify that the server returns certificate & privateKey
        assertNotNull(response.getBody().getUserCertificate());
        assertNotNull(response.getBody().getUserPrivateKey());
    }

    /**
     * Feature: PAAM - 2 (Application Registration)
     * Interface: PAAM - 3a
     * CommunicationType REST
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationUnregistrationOverRESTSuccess() throws JsonProcessingException {
        UserRegistrationRequest request = new UserRegistrationRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new UserDetails(new Credentials(username, password),
                        "", "", UserRole.APPLICATION));
        ResponseEntity<Void> response = restTemplate.postForEntity(serverAddress + unregistrationUri, request,
                Void.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

}