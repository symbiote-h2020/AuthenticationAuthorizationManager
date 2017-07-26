package eu.h2020.symbiote.security.functional.management;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.ExistingPlatformException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UnauthorizedRegistrationException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.*;
import eu.h2020.symbiote.security.functional.others.OtherFunctionalTests;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.KeyPair;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class PlatformsManagementFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(OtherFunctionalTests.class);
    private final String coreAppUsername = "testCoreAppUsername";
    private final String coreAppPassword = "testCoreAppPassword";
    private final String recoveryMail = "null@dev.null";
    private final String federatedOAuthId = "federatedOAuthId";
    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
    private final String platformOwnerUsername = "testPlatformOwnerUsername";
    private final String platformOwnerPassword = "testPlatormOwnerPassword";
    private final String platformId = "testPlatformId";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    private KeyPair platformOwnerKeyPair;
    private UserManagementRequest appUserManagementRequest;
    private RpcClient appRegistrationClient;
    private UserDetails appUserDetails;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    @Autowired
    private PlatformRepository platformRepository;

    @Autowired
    private ValidationHelper validationHelper;
    @Autowired
    private TokenIssuer tokenIssuer;

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

        // user registration useful
        appRegistrationClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                userRegistrationRequestQueue, 5000);
        appUserDetails = new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.USER);
        appUserManagementRequest = new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), appUserDetails);

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
        platformOwnerUserCredentials = new Credentials(user.getUsername(), user.getPasswordEncrypted());
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId);
        platformOwnerKeyPair = CryptoHelper.createKeyPair();

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

        // issue platform registration over AMQP
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);

        // TODO verify that released PO certificate has no CA property

        // TODO R3 verify that released platform certificate has CA property

        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationOverAMQPResponse.getPlatformId());

        // verify that PO is in repository (as PO!)
        User registeredPlatformOwner = userRepository.findOne(platformOwnerUsername);
        assertNotNull(registeredPlatformOwner);
        assertEquals(UserRole.PLATFORM_OWNER, registeredPlatformOwner.getRole());

        // verify that platform with preferred id is in repository and is tied with the given PO
        Platform registeredPlatform = platformRepository.findOne(preferredPlatformId);
        assertNotNull(registeredPlatform);
        assertEquals(platformOwnerUsername, registeredPlatform.getPlatformOwner().getUsername());

        // verify that platform oriented fields are properly stored
        assertEquals(platformInterworkingInterfaceAddress, registeredPlatform.getPlatformInterworkingInterfaceAddress());
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
        platformRegistrationOverAMQPRequest.setPlatformInstanceId("");
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        PlatformManagementResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformManagementResponse.class);

        // TODO verify that released PO certificate has no CA property

        // TODO R3 verify that released platform certificate has CA property

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
        assertEquals(UnauthorizedRegistrationException.errorMessage, errorResponse.getErrorMessage());

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
        assertEquals(UnauthorizedRegistrationException.errorMessage, errorResponse.getErrorMessage());
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
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
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
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Platform registration and platform owner registration are separate")
    public void platformRegistrationOverAMQPFailurePOUsernameExists() throws IOException, TimeoutException {
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

        // issue registration request with different preferred platform identifier but for the same PO
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(preferredPlatformId + "different");
        response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(ExistingUserException.errorMessage, errorResponse.getErrorMessage());
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

        // issue registration request with the same preferred platform identifier but different PO
        platformRegistrationOverAMQPRequest.getPlatformOwnerCredentials().setUsername
                (platformOwnerUsername + "differentOne");
        response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(ExistingPlatformException.errorMessage, errorResponse.getErrorMessage());
    }

}
