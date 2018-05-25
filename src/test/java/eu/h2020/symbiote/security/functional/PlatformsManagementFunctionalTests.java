package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMAMQPTestSuite;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.junit.Before;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class PlatformsManagementFunctionalTests extends
        AbstractAAMAMQPTestSuite {

    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
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
        User user = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.ACTIVE);
        userRepository.save(user);

    }
    @Test
    public void platformRegistrationOverAMQPSuccess() throws
            IOException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        // issue platform registration
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);
        // issue platform registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformManagementRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformManagementResponse = mapper.readValue(response,
                PlatformManagementResponse.class);

        // verify that we received the preferred platform Id
        assertEquals(preferredPlatformId, platformManagementResponse.getPlatformId());
        assertEquals(ManagementStatus.OK, platformManagementResponse.getRegistrationStatus());
        // verify that platform is in repo with proper fields
        Platform registeredPlatform = platformRepository.findOne(preferredPlatformId);
        assertNotNull(registeredPlatform);
        assertEquals(platformOwnerUsername, registeredPlatform.getPlatformOwner().getUsername());
        assertEquals(platformInstanceFriendlyName, registeredPlatform.getPlatformInstanceFriendlyName());
        assertEquals(preferredPlatformId, registeredPlatform.getPlatformInstanceId());
        assertEquals(platformInterworkingInterfaceAddress, registeredPlatform.getPlatformInterworkingInterfaceAddress());
    }

    @Test
    public void platformRegistrationOverAMQPFailErrorResponseContainerReceived() throws
            IOException {
        // verify that our platform is not in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        // issue platform registration without platform owner username
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials("", AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);
        // issue platform registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformManagementRequest), new MessageProperties())).getBody();
        ErrorResponseContainer platformRegistrationOverAMQPResponse = mapper.readValue(response,
                ErrorResponseContainer.class);
        // verify that we received ErrorResponseContainer
        assertEquals((new WrongCredentialsException()).getErrorMessage(), platformRegistrationOverAMQPResponse.getErrorMessage());
    }

    @Test
    public void sendMessageOverAMQPFailWrongMessage() throws
            IOException {
        String wrongmessage = "{wrong message json}";
        // send incorrect message over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (wrongmessage), new MessageProperties())).getBody();
        ErrorResponseContainer sspRegistrationOverAMQPResponse = mapper.readValue(response,
                ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), sspRegistrationOverAMQPResponse.getErrorCode());
    }
}
