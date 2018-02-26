package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
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
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class SmartSpaceManagementFunctionalTests extends
        AbstractAAMTestSuite {

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

        // db cleanup
        smartSpaceRepository.deleteAll();
        userRepository.deleteAll();

        //user registration useful
        User user = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
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
        assertEquals(smartSpaceGateWayAddress, registeredSmartSpace.getGatewayAddress());
        assertEquals(smartSpaceSiteLocalAddress, registeredSmartSpace.getSiteLocalAddress());
        assertEquals(true, registeredSmartSpace.isExposingSiteLocalAddress());
    }
    //TODO
    /*
    @Test
    public void sspRegistrationOverAMQPFailErrorResponseContainerReceived() throws IOException {
        //set Interworking Interfaces to empty to cause error
         smartSpaceManagementRequest.setGatewayAddress("");
        smartSpaceManagementRequest.setSiteLocalAddress("");

        // issue ssp registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(smartSpaceManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (smartSpaceManagementRequest), new MessageProperties())).getBody();
        ErrorResponseContainer sspRegistrationOverAMQPResponse = mapper.readValue(response,
                ErrorResponseContainer.class);

        // verify that we received ErrorResponseContainer
        assertEquals(InvalidArgumentsException.MISSING_INTERWORKING_INTERFACES, sspRegistrationOverAMQPResponse.getErrorMessage());
    }*/
}
