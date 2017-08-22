package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.PlatformManagementException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

    private static Log log = LogFactory.getLog(OtherListenersFunctionalTests.class);
    private final String coreAppUsername = "testCoreAppUsername";
    private final String coreAppPassword = "testCoreAppPassword";
    private final String federatedOAuthId = "federatedOAuthId";
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
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
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
        User user = new User();
        user.setUsername(platformOwnerUsername);
        user.setPasswordEncrypted(passwordEncoder.encode(platformOwnerPassword));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(user);

        // platform registration useful
        platformRegistrationOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformRegistrationRequestQueue, 5000);
        platformOwnerUserCredentials = new Credentials(platformOwnerUsername, platformOwnerPassword);
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId, OperationType.CREATE);

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
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
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
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);

        // verified that we received a generated platformId
        String generatedPlatformId = platformRegistrationOverAMQPResponse.getPlatformId();
        assertNotNull(generatedPlatformId);

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
    }

    @Test
    public void platformRegistrationOverAMQPFailureUnauthorized() throws IOException, TimeoutException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP expecting with wrong AAMOwnerUsername
        platformRegistrationOverAMQPRequest.getAAMOwnerCredentials().setUsername(AAMOwnerUsername + "somethingWrong");
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
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
        response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
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
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
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
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
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
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // verify that platform with preferred id is in repository and is tied with the given PO
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);
        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationOverAMQPResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        User user = new User();
        user.setUsername(platformOwnerUsername + "differentOne");
        user.setPasswordEncrypted(passwordEncoder.encode(platformOwnerPassword));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(user);
        // issue registration request with the same preferred platform identifier but different PO
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setUsername
                (platformOwnerUsername + "differentOne");

        response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(new PlatformManagementException().getErrorMessage(), errorResponse.getErrorMessage());
    }
}
