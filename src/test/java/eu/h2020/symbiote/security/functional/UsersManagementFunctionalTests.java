package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMAMQPTestSuite;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class UsersManagementFunctionalTests extends
        AbstractAAMAMQPTestSuite {

    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Test
    public void userManagementOverAMQPSuccess() throws
            IOException {

        Map<String, String> attributesMap = new HashMap<>();
        attributesMap.put("testKey", "testAttribute");

        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.USER,
                        AccountStatus.NEW,
                        attributesMap,
                        new HashMap<>(),
                        true,
                        false),
                OperationType.CREATE);
        // issue app registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(userManagementRequestQueue,
                new Message(mapper.writeValueAsString(userManagementRequest).getBytes(), new MessageProperties())).getBody();

        ManagementStatus appRegistrationResponse = mapper.readValue(response,
                ManagementStatus.class);
        assertEquals(ManagementStatus.OK, appRegistrationResponse);

        // verify that app really is in repository
        User registeredUser = userRepository.findOne(username);
        assertNotNull(registeredUser);
        assertEquals(UserRole.USER, registeredUser.getRole());
        assertEquals(attributesMap.get("testKey"), registeredUser.getAttributes().get("testKey"));
        // verify that the user has no certs
        assertTrue(registeredUser.getClientCertificates().isEmpty());
    }

    @Test
    public void userManagementOverAMQPFailErrorResponseContainerReceived() throws
            IOException {

        // issue user update over AMQP on not registered user
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.USER,
                        AccountStatus.NEW,
                        new HashMap<>(),
                        new HashMap<>(),
                        true,
                        false),
                OperationType.UPDATE);
        byte[] response = rabbitTemplate.sendAndReceive(userManagementRequestQueue,
                new Message(mapper.writeValueAsString(userManagementRequest).getBytes(), new MessageProperties())).getBody();
        ErrorResponseContainer userUpdateOverAMQPFailResponse = mapper.readValue(response,
                ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), userUpdateOverAMQPFailResponse.getErrorCode());
    }

    @Test
    public void sendMessageOverAMQPFailWrongMessage() throws
            IOException {
        String wrongmessage = "{wrong message json}";
        // send incorrect message over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(userManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (wrongmessage), new MessageProperties())).getBody();
        ErrorResponseContainer sspRegistrationOverAMQPResponse = mapper.readValue(response,
                ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), sspRegistrationOverAMQPResponse.getErrorCode());
    }

    @Test
    public void userManagementOverRESTSuccess() throws
            AAMException {
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.USER,
                        AccountStatus.NEW,
                        new HashMap<>(),
                        new HashMap<>(),
                        true,
                        false),
                OperationType.CREATE);
        ManagementStatus managementStatus = aamClient.manageUser(userManagementRequest);
        assertTrue(ManagementStatus.OK.equals(managementStatus));
        assertTrue(userRepository.exists(username));
    }

    @Test(expected = AAMException.class)
    public void userManagementOverRESTFail() throws
            AAMException {
        assertFalse(userRepository.exists(username));
        //update not existing user to create error
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials("", password),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.USER,
                        AccountStatus.NEW,
                        new HashMap<>(),
                        new HashMap<>(),
                        true,
                        false),
                OperationType.UPDATE);
        aamClient.manageUser(userManagementRequest);
    }
}
