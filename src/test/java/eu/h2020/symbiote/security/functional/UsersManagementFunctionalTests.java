package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMAMQPTestSuite;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class UsersManagementFunctionalTests extends
        AbstractAAMAMQPTestSuite {

    private static Log log = LogFactory.getLog(OtherListenersFunctionalTests.class);
    private final String federatedOAuthId = "federatedOAuthId";
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    protected String platformAAMSuffixAtInterWorkingInterface;
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    protected String coreInterfaceAddress;
    @Value("${rabbit.queue.get.user.details}")
    private String getUserDetailsQueue;
    private UserManagementRequest appUserRegistrationRequest;
    private UserManagementRequest appUserUpdateRequest;
    private UserDetails appUserDetails;
    @Autowired
    private RabbitTemplate rabbitTemplate;

    private Connection connection;

    private RpcClient getUserDetailsClient;
    @Override
    @Before
    public void setUp() throws
            Exception {
        super.setUp();
        // hack: set deployment type back to CORE
        ReflectionTestUtils.setField(usersManagementService, "deploymentType", IssuingAuthorityType.CORE);
        // user registration useful
        appUserDetails = new UserDetails(new Credentials(
                username, password), recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>());
        appUserRegistrationRequest = new UserManagementRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, password), appUserDetails, OperationType.CREATE);
        appUserUpdateRequest = new UserManagementRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, password), appUserDetails, OperationType.UPDATE);
        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));
        getUserDetailsClient = new RpcClient(getConnection().createChannel(), "", getUserDetailsQueue, 5000);
    }

    public Connection getConnection() throws IOException, TimeoutException {
        if (connection == null) {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost(rabbitTemplate.getConnectionFactory().getHost());
            factory.setUsername(rabbitTemplate.getConnectionFactory().getUsername());
            factory.setPassword("guest");
            this.connection = factory.newConnection();
        }
        return this.connection;
    }

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
                        attributesMap,
                        new HashMap<>()),
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
                        new HashMap<>(),
                        new HashMap<>()),
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
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        ManagementStatus managementStatus = aamClient.manageUser(userManagementRequest);
        assertTrue(ManagementStatus.OK.equals(managementStatus));
        assertTrue(userRepository.exists(username));
    }

    @Test(expected = AAMException.class)
    public void userManagementOverRESTFailProperPayloadReceived() throws
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
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.UPDATE);
        aamClient.manageUser(userManagementRequest);
    }

    //TODO change getUserDetails
    @Test
    public void requestUserDetailsUsingRPCClientOverAMQPSuccess() throws
            IOException,
            TimeoutException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = getUserDetailsClient.primitiveCall(mapper.writeValueAsBytes(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                null, null
        )));

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        log.info("Retrieved username is: " + userDetails.getUserDetails().getCredentials().getUsername());
        assertEquals(username, userDetails.getUserDetails().getCredentials().getUsername());
        assertEquals(HttpStatus.OK, userDetails.getHttpStatus());
    }

    @Test
    public void requestUserDetailsOverAMQPSuccess() throws
            IOException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsBytes(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                null, null
        )), new MessageProperties())).getBody();
        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        log.info("Retrieved username is: " + userDetails.getUserDetails().getCredentials().getUsername());
        assertEquals(username, userDetails.getUserDetails().getCredentials().getUsername());
        assertEquals(HttpStatus.OK, userDetails.getHttpStatus());
    }


    @Test
    public void requestUserDetailsOverAMQPFailsForNotExistingUser() throws
            IOException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsBytes(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials("NotExistingUser", "Password"),
                null, null
        )), new MessageProperties())).getBody();

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        assertEquals(HttpStatus.BAD_REQUEST, userDetails.getHttpStatus());
    }

    @Test
    public void requestUserDetailsOverAMQPFailsForWrongPassword() throws
            IOException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsBytes(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, "wrongPassword"),
                null, null
        )), new MessageProperties())).getBody();

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        assertEquals(HttpStatus.UNAUTHORIZED, userDetails.getHttpStatus());
    }

    @Test
    public void requestUserDetailsOverAMQPFailsForRequestWithoutUserCredentials() throws
            IOException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), null,
                null, null
        )).getBytes(), new MessageProperties())).getBody();

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);
        assertEquals(HttpStatus.UNAUTHORIZED, userDetails.getHttpStatus());
    }

    @Test
    public void getUserDetailsFailsForIncorrectAdminPassword() throws
            IOException {

        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, "wrongPassword"), new Credentials(username, password),
                null, null
        )).getBytes(), new MessageProperties())).getBody();

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);
        assertEquals(HttpStatus.FORBIDDEN, userDetails.getHttpStatus());
    }


}
