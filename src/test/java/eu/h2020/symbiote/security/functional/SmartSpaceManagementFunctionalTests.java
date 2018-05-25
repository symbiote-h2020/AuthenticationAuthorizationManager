package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMAMQPTestSuite;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.SmartSpaceManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.SmartSpaceManagementResponse;
import eu.h2020.symbiote.security.repositories.SmartSpaceRepository;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
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
public class SmartSpaceManagementFunctionalTests extends
        AbstractAAMAMQPTestSuite {

    private Credentials smartSpaceOwnerUserCredentials;
    private SmartSpaceManagementRequest smartSpaceManagementRequest;
    @Autowired
    private SmartSpaceRepository smartSpaceRepository;
    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        //user registration useful
        User user = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.NEW);
        userRepository.save(user);

        // smartSpace registration useful
        smartSpaceOwnerUserCredentials = new Credentials(smartSpaceOwnerUsername, smartSpaceOwnerPassword);
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.CREATE,
                preferredSmartSpaceId,
                true);
    }

    @Test
    public void smartSpaceRegistrationOverAMQPSuccess() throws IOException {
        // verify that our ssp is not in repository and that our sspOwner is in repository
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId));
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
        User sspOwner = userRepository.findOne(smartSpaceOwnerUsername);
        assertTrue(sspOwner.getOwnedServices().isEmpty());

        // issue ssp registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(smartSpaceManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (smartSpaceManagementRequest), new MessageProperties())).getBody();
        SmartSpaceManagementResponse sspRegistrationOverAMQPResponse = mapper.readValue(response,
                SmartSpaceManagementResponse.class);

        // verify that we received the preferred sspId
        assertEquals(preferredSmartSpaceId, sspRegistrationOverAMQPResponse.getSmartSpaceId());
        assertEquals(ManagementStatus.OK, sspRegistrationOverAMQPResponse.getManagementStatus());
        // verify that ssp is in repo with proper fields
        SmartSpace registeredSmartSpace = smartSpaceRepository.findOne(preferredSmartSpaceId);
        assertNotNull(registeredSmartSpace);
        assertEquals(smartSpaceOwnerUsername, registeredSmartSpace.getSmartSpaceOwner().getUsername());
        assertEquals(smartSpaceInstanceFriendlyName, registeredSmartSpace.getInstanceFriendlyName());
        assertEquals(smartSpaceGateWayAddress, registeredSmartSpace.getExternalAddress());
        assertEquals(smartSpaceSiteLocalAddress, registeredSmartSpace.getSiteLocalAddress());
        assertEquals(true, registeredSmartSpace.isExposingSiteLocalAddress());
    }

    @Test
    public void sspRegistrationOverAMQPFailErrorResponseContainerReceived() throws IOException,
            InvalidArgumentsException {
        //set Interworking Interfaces to empty to cause error
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, "wrongpassword"),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.CREATE,
                preferredSmartSpaceId,
                false);

        // issue ssp registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(smartSpaceManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (smartSpaceManagementRequest), new MessageProperties())).getBody();
        ErrorResponseContainer sspRegistrationOverAMQPResponse = mapper.readValue(response,
                ErrorResponseContainer.class);

        // verify that we received ErrorResponseContainer
        assertEquals((new WrongCredentialsException()).getErrorMessage(), sspRegistrationOverAMQPResponse.getErrorMessage());
    }

    @Test
    public void sendMessageOverAMQPFailWrongMessage() throws
            IOException {
        String wrongmessage = "{wrong message json}";
        // send incorrect message over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(smartSpaceManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (wrongmessage), new MessageProperties())).getBody();
        ErrorResponseContainer sspRegistrationOverAMQPResponse = mapper.readValue(response,
                ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), sspRegistrationOverAMQPResponse.getErrorCode());
    }
}
