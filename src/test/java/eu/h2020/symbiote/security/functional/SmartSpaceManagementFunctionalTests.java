package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.SspManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.SspManagementResponse;
import eu.h2020.symbiote.security.repositories.SmartSpaceRepository;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.junit.Before;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class SmartSpaceManagementFunctionalTests extends
        AbstractAAMTestSuite {

    private Credentials sspOwnerUserCredentials;
    private SspManagementRequest sspManagementRequest;
    @Autowired
    private SmartSpaceRepository smartSpaceRepository;
    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // db cleanup
        smartSpaceRepository.deleteAll();
        userRepository.deleteAll();

        //user registration useful
        User user = createUser(sspOwnerUsername, sspOwnerPassword, recoveryMail, UserRole.SSP_OWNER);
        userRepository.save(user);

        // ssp registration useful
        sspOwnerUserCredentials = new Credentials(sspOwnerUsername, sspOwnerPassword);
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.CREATE,
                preferredSspId,
                true);
    }

    @Test
    public void sspRegistrationOverAMQPSuccess() throws IOException {
        // verify that our ssp is not in repository and that our sspOwner is in repository
        assertFalse(smartSpaceRepository.exists(preferredSspId));
        assertTrue(userRepository.exists(sspOwnerUsername));
        User sspOwner = userRepository.findOne(sspOwnerUsername);
        assertTrue(sspOwner.getOwnedServices().isEmpty());

        // issue ssp registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(sspManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (sspManagementRequest), new MessageProperties())).getBody();
        SspManagementResponse sspRegistrationOverAMQPResponse = mapper.readValue(response,
                SspManagementResponse.class);

        // verify that we received the preferred sspId
        assertEquals(preferredSspId, sspRegistrationOverAMQPResponse.getSspId());
        assertEquals(ManagementStatus.OK, sspRegistrationOverAMQPResponse.getManagementStatus());
        // verify that ssp is in repo with proper fields
        SmartSpace registeredSsp = smartSpaceRepository.findOne(preferredSspId);
        assertNotNull(registeredSsp);
        assertEquals(sspOwnerUsername, registeredSsp.getSspOwner().getUsername());
        assertEquals(sspInstanceFriendlyName, registeredSsp.getSspInstanceFriendlyName());
        assertEquals(sspExternalInterworkingInterfaceAddress, registeredSsp.getSspExternalInterworkingInterfaceAddress());
        assertEquals(sspInternalInterworkingInterfaceAddress, registeredSsp.getSspInternalInterworkingInterfaceAddress());
        assertEquals(true, registeredSsp.isExposedInternalInterworkingInterfaceAddress());
    }

    @Test
    public void sspRegistrationOverAMQPFailErrorResponseContainerReceived() throws IOException {
        //set Interworking Interfaces to empty to cause error
        sspManagementRequest.setSspExternalInterworkingInterfaceAddress("");
        sspManagementRequest.setSspInternalInterworkingInterfaceAddress("");

        // issue ssp registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(sspManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (sspManagementRequest), new MessageProperties())).getBody();
        ErrorResponseContainer sspRegistrationOverAMQPResponse = mapper.readValue(response,
                ErrorResponseContainer.class);

        // verify that we received ErrorResponseContainer
        assertEquals(InvalidArgumentsException.MISSING_INTERWORKING_INTERFACES, sspRegistrationOverAMQPResponse.getErrorMessage());
    }
}
