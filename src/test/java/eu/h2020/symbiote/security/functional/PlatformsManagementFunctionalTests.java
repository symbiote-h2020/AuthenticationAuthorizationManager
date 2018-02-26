package eu.h2020.symbiote.security.functional;

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
import org.junit.Before;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;

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
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    String coreInterfaceAddress;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    private PlatformManagementRequest platformUpdateOverAMQPRequest;
    private PlatformManagementRequest platformDeleteOverAMQPRequest;
    @Autowired
    private PlatformRepository platformRepository;
    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // db cleanup
        platformRepository.deleteAll();
        userRepository.deleteAll();

        //user registration useful
        User user = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(user);

        // platform registration useful
        platformOwnerUserCredentials = new Credentials(platformOwnerUsername, platformOwnerPassword);
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);
        platformUpdateOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.UPDATE);
        platformDeleteOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.DELETE);

    }


    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPWithPreferredPlatformIdSuccess() throws IOException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        User platformOwner = userRepository.findOne(platformOwnerUsername);
        assertTrue(platformOwner.getOwnedServices().isEmpty());

        // issue platform registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);

        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationOverAMQPResponse.getPlatformId());

        // verify that PO is in repository (as PO!)
        User platformOwnerFromRepository = userRepository.findOne(platformOwnerUsername);
        assertNotNull(platformOwnerFromRepository);
        assertEquals(UserRole.SERVICE_OWNER, platformOwnerFromRepository.getRole());

        // verify that platform with preferred id is in repository and is tied with the given PO
        Platform registeredPlatform = platformRepository.findOne(preferredPlatformId);
        assertNotNull(registeredPlatform);
        // verify that platform oriented fields are properly stored
        assertEquals(platformInterworkingInterfaceAddress, registeredPlatform.getPlatformInterworkingInterfaceAddress());

        // verify that PO has this platform in his collection
        User platformOwnerFromPlatformEntity = registeredPlatform.getPlatformOwner();
        assertEquals(platformOwnerUsername, platformOwnerFromPlatformEntity.getUsername());
        assertTrue(platformOwnerFromPlatformEntity.getOwnedServices().contains(preferredPlatformId));

        // verify that PO was properly updated in repository with new platform ownership
        platformOwnerFromRepository = userRepository.findOne(platformOwnerUsername);
        assertEquals(platformOwnerUsername, platformOwnerFromRepository.getUsername());
        assertFalse(platformOwnerFromRepository.getOwnedServices().isEmpty());
        assertTrue(platformOwnerFromRepository.getOwnedServices().contains(preferredPlatformId));

        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPWithGeneratedPlatformIdSuccess() throws IOException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without preferred platform identifier
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                "",
                OperationType.CREATE);
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);

        // verified that we received a generated platformId
        String generatedPlatformId = platformRegistrationOverAMQPResponse.getPlatformId();
        assertFalse(generatedPlatformId.isEmpty());

        // verify that PO is in repository (as PO!)
        User registeredPlatformOwner = userRepository.findOne(platformOwnerUsername);
        assertNotNull(registeredPlatformOwner);
        assertEquals(UserRole.SERVICE_OWNER, registeredPlatformOwner.getRole());
        assertTrue(registeredPlatformOwner.getOwnedServices().contains(generatedPlatformId));

        // verify that platform with the generated id is in repository and is tied with the given PO
        Platform registeredPlatform = platformRepository.findOne(generatedPlatformId);
        assertNotNull(registeredPlatform);
        assertEquals(platformOwnerUsername, registeredPlatform.getPlatformOwner().getUsername());

        // verify that platform oriented fields are properly stored
        assertEquals(platformInterworkingInterfaceAddress, registeredPlatform.getPlatformInterworkingInterfaceAddress());
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());
    }

    @Test
    public void platformRegistrationOverAMQPFailWrongPlatformId() throws IOException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without preferred platform identifier
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                "Wrong_platform#id",
                OperationType.CREATE);
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        ErrorResponseContainer errorResponse = mapper.readValue(response,
                ErrorResponseContainer.class);

        assertEquals(ServiceManagementException.AWKWARD_SERVICE, errorResponse.getErrorMessage());
    }

    @Test
    public void platformManageOverAMQPMissingCredentials() throws IOException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setUsername("");

        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        ErrorResponseContainer errorResponse = mapper.readValue(response,
                ErrorResponseContainer.class);

        assertEquals(InvalidArgumentsException.MISSING_USERNAME_OR_PASSWORD, errorResponse.getErrorMessage());
    }

    @Test
    public void platformManageOverAMQPFailNotExistingUser() throws IOException {
        // verify that our platformOwner is in repository
        assertFalse(userRepository.exists(wrongUsername));
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setUsername(wrongUsername);

        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        ErrorResponseContainer errorResponse = mapper.readValue(response,
                ErrorResponseContainer.class);

        assertEquals(new NotExistingUserException().getErrorMessage(), errorResponse.getErrorMessage());
    }

    @Test
    public void platformManageOverAMQPFailWrongPO() throws IOException {
        // verify that  platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));
        //create the platform by platformOwner
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformManagementResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        assertEquals(ManagementStatus.OK, platformManagementResponse.getRegistrationStatus());

        // create other platformOwner
        String otherPlatformOwnerUsername = "otherPlatformOwner";
        User otherPlatformOwner = createUser(otherPlatformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(otherPlatformOwner);
        Credentials otherPlatformOwnerCredentials = new Credentials(otherPlatformOwnerUsername, platformOwnerPassword);
        // verify that other platformOwner is in repository
        assertTrue(userRepository.exists(otherPlatformOwnerUsername));

        //try to update platform by other platformOwner (without rights to this platform)
        PlatformManagementRequest platformUpdateOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                otherPlatformOwnerCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.UPDATE);
        response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformUpdateOverAMQPRequest), new MessageProperties())).getBody();
        ErrorResponseContainer errorResponse = mapper.readValue(response,
                ErrorResponseContainer.class);
        assertEquals(ServiceManagementException.NOT_OWNED_SERVICE, errorResponse.getErrorMessage());

        //try to delete platform by other platformOwner (without rights to this platform)
        PlatformManagementRequest platformDeleteOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                otherPlatformOwnerCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.DELETE);
        response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformDeleteOverAMQPRequest), new MessageProperties())).getBody();
        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(ServiceManagementException.NOT_OWNED_SERVICE, errorResponse.getErrorMessage());
    }

    @Test
    public void platformManageOverAMQPFailwrongPassword() throws IOException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setPassword(wrongPassword);

        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        ErrorResponseContainer errorResponse = mapper.readValue(response,
                ErrorResponseContainer.class);

        assertEquals(new WrongCredentialsException().getErrorMessage(), errorResponse.getErrorMessage());
    }

    @Test
    public void platformManageOverAMQPFailUserNotPlatformOwner() throws IOException {
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        assertTrue(userRepository.exists(username));
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setUsername(username);
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setPassword(password);

        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        ErrorResponseContainer errorResponse = mapper.readValue(response,
                ErrorResponseContainer.class);

        assertEquals(new WrongCredentialsException().getErrorMessage(), errorResponse.getErrorMessage());
    }

    @Test
    public void platformRegistrationOverAMQPFailureUnauthorized() throws IOException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP expecting with wrong AAMOwnerUsername
        platformRegistrationOverAMQPRequest.getAamOwnerCredentials().setUsername(AAMOwnerUsername + "somethingWrong");
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();

        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(new WrongCredentialsException().getErrorMessage(), errorResponse.getErrorMessage());

        // issue platform registration over AMQP expecting with wrong AAMOwnerUsername
        platformRegistrationOverAMQPRequest.getAamOwnerCredentials().setUsername(AAMOwnerUsername);
        platformRegistrationOverAMQPRequest.getAamOwnerCredentials().setPassword(AAMOwnerPassword + "somethingWrong");
        response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();

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
    public void platformRegistrationOverAMQPFailureMissingAAMURL() throws IOException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without required Platform's AAM URL
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                "",
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(InvalidArgumentsException.MISSING_PLATFORM_AAM_URL, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailureMissingFriendlyName() throws IOException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without required Platform's instance friendly name
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress,
                "",
                preferredPlatformId,
                OperationType.CREATE);
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(InvalidArgumentsException.MISSING_INSTANCE_FRIENDLY_NAME, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailurePreferredPlatformIdExists() throws IOException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();

        // verify that platform with preferred id is in repository and is tied with the given PO
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationOverAMQPResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        User user = createUser(platformOwnerUsername + "differentOne", platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(user);
        // issue registration request with the same preferred platform identifier but different PO
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setUsername
                (platformOwnerUsername + "differentOne");

        response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(ServiceManagementException.SERVICE_EXISTS, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailurePlatformInterworkingInterfaceInUse() throws
            IOException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        // issue platform registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();

        // verify that platform with preferred id is in repository and is tied with the given PO
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationOverAMQPResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        User user = createUser(platformOwnerUsername + "differentOne", platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(user);
        // issue registration request with the same preferred platform identifier but different PO
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                "differentId",
                OperationType.CREATE);
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setUsername
                (platformOwnerUsername + "differentOne");
        // we try to use the same Interworking Interface!
        response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, errorResponse.getErrorMessage());
    }

    @Test
    public void platformUpdateOverAMQPSuccess() throws IOException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        //ensure platform is registered
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());

        platformUpdateOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress,// + "differentOne",
                platformInstanceFriendlyName + "differentOne",
                preferredPlatformId,
                OperationType.UPDATE);
        byte[] response2 = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformUpdateOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformRegistrationOverAMQPResponse2 = mapper.readValue(response2,
                PlatformManagementResponse.class);
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse2.getRegistrationStatus());
    }

    @Test
    public void platformUpdateOverAMQPFailNotExistingPlatform() throws IOException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        //ensure platform is registered
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());

        platformUpdateOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                platformId + "differentOne",
                OperationType.UPDATE);
        byte[] response2 = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformUpdateOverAMQPRequest), new MessageProperties())).getBody();
        ErrorResponseContainer errorResponse = mapper.readValue(response2, ErrorResponseContainer.class);
        assertEquals(ServiceManagementException.SERVICE_NOT_EXIST, errorResponse.getErrorMessage());
    }

    @Test
    public void platformDeleteOverAMQPSuccess() throws IOException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        //ensure platform is registered
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());

        //register second platform
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress + "/second",
                platformInstanceFriendlyName,
                preferredPlatformId + "2",
                OperationType.CREATE);
        byte[] response2 = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        platformRegistrationOverAMQPResponse = mapper.readValue(response2,
                PlatformManagementResponse.class);
        //ensure platform is registered
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());

        // delete platform 1
        response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformDeleteOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformRegistrationOverAMQPResponse2 = mapper.readValue(response,
                PlatformManagementResponse.class);
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse2.getRegistrationStatus());

        // delete platform 2
        platformDeleteOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId + "2",
                OperationType.DELETE);
        response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformDeleteOverAMQPRequest), new MessageProperties())).getBody();
        platformRegistrationOverAMQPResponse2 = mapper.readValue(response,
                PlatformManagementResponse.class);
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse2.getRegistrationStatus());

        assertTrue(userRepository.findOne(platformOwnerUsername).getOwnedServices().isEmpty());
    }

    @Test
    public void platformDeleteOverAMQPFailNotExistingPlatform() throws IOException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        //ensure platform is registered
        assertEquals(ManagementStatus.OK, platformRegistrationOverAMQPResponse.getRegistrationStatus());

        platformDeleteOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                platformId + "different",
                OperationType.DELETE);
        byte[] response2 = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformDeleteOverAMQPRequest), new MessageProperties())).getBody();
        ErrorResponseContainer errorResponse = mapper.readValue(response2, ErrorResponseContainer.class);
        assertEquals(ServiceManagementException.SERVICE_NOT_EXIST, errorResponse.getErrorMessage());
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
