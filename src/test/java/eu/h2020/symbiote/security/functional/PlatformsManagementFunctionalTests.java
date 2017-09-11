package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class PlatformsManagementFunctionalTests extends
        AbstractAAMTestSuite {

    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
    private final String platformId = "testPlatformId";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    private RpcClient platformManagementOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    private PlatformManagementRequest platformUpdateOverAMQPRequest;
    private PlatformManagementRequest platformDeleteOverAMQPRequest;
    @Autowired
    private PlatformRepository platformRepository;

    @Bean
    DummyPlatformAAM getDummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // db cleanup
        platformRepository.deleteAll();
        userRepository.deleteAll();

        //user registration useful
        User user = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.PLATFORM_OWNER);
        userRepository.save(user);

        // platform registration useful
        platformManagementOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformManagementRequestQueue, 5000);
        platformOwnerUserCredentials = new Credentials(platformOwnerUsername, platformOwnerPassword);
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId, OperationType.CREATE);
        platformUpdateOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId, OperationType.UPDATE);
        platformDeleteOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId, OperationType.DELETE);

    }


    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPWithPreferredPlatformIdSuccess() throws IOException, TimeoutException {


        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        User platformOwner = userRepository.findOne(platformOwnerUsername);
        assertTrue(platformOwner.getOwnedPlatforms().isEmpty());

        // issue platform registration over AMQP
        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);

        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationOverAMQPResponse.getPlatformId());

        // verify that PO is in repository (as PO!)
        User platformOwnerFromRepository = userRepository.findOne(platformOwnerUsername);
        assertNotNull(platformOwnerFromRepository);
        assertEquals(UserRole.PLATFORM_OWNER, platformOwnerFromRepository.getRole());

        // verify that platform with preferred id is in repository and is tied with the given PO
        Platform registeredPlatform = platformRepository.findOne(preferredPlatformId);
        assertNotNull(registeredPlatform);
        // verify that platform oriented fields are properly stored
        assertEquals(platformInterworkingInterfaceAddress, registeredPlatform.getPlatformInterworkingInterfaceAddress());

        // verify that PO has this platform in his collection
        User platformOwnerFromPlatformEntity = registeredPlatform.getPlatformOwner();
        assertEquals(platformOwnerUsername, platformOwnerFromPlatformEntity.getUsername());
        assertTrue(platformOwnerFromPlatformEntity.getOwnedPlatforms().containsKey(preferredPlatformId));

        // verify that DBRef is working two-way
        Platform platformFromPlatformOwnerFromPlatformEntity = platformOwnerFromPlatformEntity.getOwnedPlatforms().get(preferredPlatformId);
        assertEquals(preferredPlatformId, platformFromPlatformOwnerFromPlatformEntity.getPlatformInstanceId());

        // verify that PO was properly updated in repository with new platform ownership
        platformOwnerFromRepository = userRepository.findOne(platformOwnerUsername);
        assertEquals(platformOwnerUsername, platformOwnerFromRepository.getUsername());
        assertFalse(platformOwnerFromRepository.getOwnedPlatforms().isEmpty());
        assertNotNull(platformOwnerFromRepository.getOwnedPlatforms().get(preferredPlatformId));

        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPWithGeneratedPlatformIdSuccess() throws IOException, TimeoutException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without preferred platform identifier
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(platformId);
        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);

        // verified that we received a generated platformId
        String generatedPlatformId = platformRegistrationOverAMQPResponse.getPlatformId();
        assertFalse(generatedPlatformId.isEmpty());

        // verify that PO is in repository (as PO!)
        User registeredPlatformOwner = userRepository.findOne(platformOwnerUsername);
        assertNotNull(registeredPlatformOwner);
        assertEquals(UserRole.PLATFORM_OWNER, registeredPlatformOwner.getRole());

        // verify that platform with the generated id is in repository and is tied with the given PO
        Platform registeredPlatform = platformRepository.findOne(generatedPlatformId);
        assertNotNull(registeredPlatform);
        assertEquals(platformOwnerUsername, registeredPlatform.getPlatformOwner().getUsername());

        // verify that platform oriented fields are properly stored
        assertEquals(platformInterworkingInterfaceAddress, registeredPlatform.getPlatformInterworkingInterfaceAddress());
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());
    }

    @Test
    public void platformManageOverAMQPMissingCredentials() throws IOException, TimeoutException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setUsername("");

        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        ErrorResponseContainer errorResponse = mapper.readValue(response,
                ErrorResponseContainer.class);

        assertEquals(new InvalidArgumentsException().getErrorMessage(), errorResponse.getErrorMessage());
    }

    @Test
    public void platformManageOverAMQPFailNotExistingUser() throws IOException, TimeoutException {
        // verify that our platformOwner is in repository
        assertFalse(userRepository.exists(wrongUsername));
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setUsername(wrongUsername);

        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        ErrorResponseContainer errorResponse = mapper.readValue(response,
                ErrorResponseContainer.class);

        assertEquals(new NotExistingUserException().getErrorMessage(), errorResponse.getErrorMessage());
    }

    @Test
    public void platformManageOverAMQPFailwrongPassword() throws IOException, TimeoutException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setPassword(wrongPassword);

        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        ErrorResponseContainer errorResponse = mapper.readValue(response,
                ErrorResponseContainer.class);

        assertEquals(new WrongCredentialsException().getErrorMessage(), errorResponse.getErrorMessage());
    }

    @Test
    public void platformRegistrationOverAMQPFailureUnauthorized() throws IOException, TimeoutException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP expecting with wrong AAMOwnerUsername
        platformRegistrationOverAMQPRequest.getAAMOwnerCredentials().setUsername(AAMOwnerUsername + "somethingWrong");
        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(new WrongCredentialsException().getErrorMessage(), errorResponse.getErrorMessage());

        // issue platform registration over AMQP expecting with wrong AAMOwnerUsername
        platformRegistrationOverAMQPRequest.getAAMOwnerCredentials().setUsername(AAMOwnerUsername);
        platformRegistrationOverAMQPRequest.getAAMOwnerCredentials().setPassword(AAMOwnerPassword + "somethingWrong");
        response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // verify error response
        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(new WrongCredentialsException().getErrorMessage(), errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailureMissingAAMURL() throws IOException, TimeoutException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without required Platform's AAM URL
        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress("");
        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(InvalidArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailureMissingFriendlyName() throws IOException, TimeoutException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without required Platform's instance friendly name
        platformRegistrationOverAMQPRequest.setPlatformInstanceFriendlyName("");
        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(InvalidArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailurePreferredPlatformIdExists() throws IOException, TimeoutException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // verify that platform with preferred id is in repository and is tied with the given PO
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationOverAMQPResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        User user = createUser(platformOwnerUsername + "differentOne", platformOwnerPassword, recoveryMail, UserRole.PLATFORM_OWNER);
        userRepository.save(user);
        // issue registration request with the same preferred platform identifier but different PO
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setUsername
                (platformOwnerUsername + "differentOne");

        response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(new PlatformManagementException().getErrorMessage(), errorResponse.getErrorMessage());
    }

    @Test
    public void platformUpdateOverAMQPSuccess() throws IOException, TimeoutException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        //ensure platform is registered
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());

        platformUpdateOverAMQPRequest.setPlatformInstanceFriendlyName(platformInstanceFriendlyName + "differentOne");
        platformUpdateOverAMQPRequest.setPlatformInterworkingInterfaceAddress(platformInterworkingInterfaceAddress + "differentOne");
        byte[] response2 = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformUpdateOverAMQPRequest).getBytes());
        PlatformManagementResponse platformRegistrationOverAMQPResponse2 = mapper.readValue(response2,
                PlatformManagementResponse.class);
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse2.getRegistrationStatus());
    }

    @Test
    public void platformUpdateOverAMQPFailNotExistingPlatform() throws IOException, TimeoutException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        //ensure platform is registered
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());

        platformUpdateOverAMQPRequest.setPlatformInstanceId(platformId + "differentOne");
        byte[] response2 = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformUpdateOverAMQPRequest).getBytes());
        ErrorResponseContainer errorResponse = mapper.readValue(response2, ErrorResponseContainer.class);
        assertEquals(new PlatformManagementException().getErrorMessage(), errorResponse.getErrorMessage());
    }

    @Test
    public void platformDeleteOverAMQPSuccess() throws IOException, TimeoutException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        //ensure platform is registered
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());

        byte[] response2 = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformDeleteOverAMQPRequest).getBytes());
        PlatformManagementResponse platformRegistrationOverAMQPResponse2 = mapper.readValue(response2,
                PlatformManagementResponse.class);
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse2.getRegistrationStatus());

        assertTrue(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().isEmpty());
    }

    @Test
    public void platformDeleteOverAMQPFailNotExistingPlatform() throws IOException, TimeoutException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        byte[] response = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        //ensure platform is registered
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());

        platformDeleteOverAMQPRequest.setPlatformInstanceId(platformId + "different");
        byte[] response2 = platformManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformDeleteOverAMQPRequest).getBytes());
        ErrorResponseContainer errorResponse = mapper.readValue(response2, ErrorResponseContainer.class);
        assertEquals(new PlatformManagementException().getErrorMessage(), errorResponse.getErrorMessage());
    }

    @Test
    public void platformManagementControllerSucceedsManagingRegistrationRequest() throws AAMException {
        PlatformManagementRequest platformRegistrationRequest;
        platformRegistrationRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInstanceFriendlyName,
                preferredPlatformId, OperationType.CREATE);

        ManagementStatus response = aamClient.managePlatform(platformRegistrationRequest);
        assertEquals(ManagementStatus.OK, response);
    }

    @Test(expected = AAMException.class)
    public void platformManagementControllerFailsManagingIncorrectRegistrationRequest() throws AAMException {
        PlatformManagementRequest IncorrectPlatformRegistrationRequest;
        IncorrectPlatformRegistrationRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(wrongUsername, wrongPassword),
                platformInstanceFriendlyName,
                preferredPlatformId, OperationType.CREATE);

        ManagementStatus status = aamClient.managePlatform(IncorrectPlatformRegistrationRequest);
        assertEquals(ManagementStatus.ERROR, status);
    }

}
