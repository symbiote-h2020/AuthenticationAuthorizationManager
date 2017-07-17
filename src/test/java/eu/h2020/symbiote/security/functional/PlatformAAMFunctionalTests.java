package eu.h2020.symbiote.security.functional;

import com.fasterxml.jackson.core.JsonProcessingException;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.RegistrationStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.interfaces.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.repositories.entities.User;
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
    public void userRegistrationOverRESTSuccess() throws JsonProcessingException {
        String testAppUsername = "NewApplication";
        UserManagementRequest request = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new UserDetails(new Credentials(testAppUsername, "NewPassword"), "", "", UserRole.USER));
        // verify that app is not in the repository
        User registeredUser = userRepository.findOne(testAppUsername);
        assertNull(registeredUser);

        ResponseEntity<RegistrationStatus> response = restTemplate.postForEntity(serverAddress +
                registrationUri, request, RegistrationStatus.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        // verify that app really is in repository
        registeredUser = userRepository.findOne(testAppUsername);
        assertNotNull(registeredUser);
        assertEquals(UserRole.USER, registeredUser.getRole());

        // verify that the server returns certificate & privateKey
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
    public void userUnregistrationOverRESTSuccess() throws JsonProcessingException {
        UserManagementRequest request = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new UserDetails(new Credentials(username, password),
                        "", "", UserRole.USER));
        ResponseEntity<Void> response = restTemplate.postForEntity(serverAddress + unregistrationUri, request,
                Void.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

}