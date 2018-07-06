package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMAMQPTestSuite;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.UserDetailsResponse;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
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
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class GetUserDetailsFunctionalTests extends AbstractAAMAMQPTestSuite {

    @Autowired
    private RabbitTemplate rabbitTemplate;

    private Connection connection;

    private RpcClient getUserDetailsClient;

    @Override
    @Before
    public void setUp() throws
            Exception {
        super.setUp();
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
    public void getUserDetailsUsingRPCClientOverAMQPSuccess() throws
            IOException,
            TimeoutException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER, AccountStatus.ACTIVE);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = getUserDetailsClient.primitiveCall(mapper.writeValueAsBytes(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                null, OperationType.READ
        )));

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        assertEquals(username, userDetails.getUserDetails().getCredentials().getUsername());
        assertEquals(recoveryMail, userDetails.getUserDetails().getRecoveryMail());
        assertEquals(UserRole.USER, userDetails.getUserDetails().getRole());
        assertTrue(userDetails.getUserDetails().getCredentials().getPassword().isEmpty());
        assertEquals(HttpStatus.OK, userDetails.getHttpStatus());
    }

    @Test
    public void getUserDetailsOverAMQPForbiddenForInactiveAccount() throws
            IOException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER, AccountStatus.NEW);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsBytes(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                null, OperationType.READ
        )), new MessageProperties())).getBody();
        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        assertEquals(UserRole.USER, userDetails.getUserDetails().getRole());
        assertTrue(userDetails.getUserDetails().getCredentials().getPassword().isEmpty());
        assertEquals(AccountStatus.NEW, userDetails.getUserDetails().getStatus());
        assertEquals(HttpStatus.FORBIDDEN, userDetails.getHttpStatus());
    }

    @Test
    public void getUserDetailsOverAMQPSuccessForActiveAccount() throws
            IOException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER, AccountStatus.ACTIVE);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsBytes(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                null, OperationType.READ
        )), new MessageProperties())).getBody();
        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        assertEquals(username, userDetails.getUserDetails().getCredentials().getUsername());
        assertEquals(recoveryMail, userDetails.getUserDetails().getRecoveryMail());
        assertEquals(UserRole.USER, userDetails.getUserDetails().getRole());
        assertTrue(userDetails.getUserDetails().getCredentials().getPassword().isEmpty());
        assertEquals(HttpStatus.OK, userDetails.getHttpStatus());
    }

    @Test
    public void getUserDetailsOverAMQAsAdminPSuccess() throws
            IOException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER, AccountStatus.NEW);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsBytes(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, "irrelevant"),
                null, OperationType.FORCE_READ
        )), new MessageProperties())).getBody();
        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        assertEquals(username, userDetails.getUserDetails().getCredentials().getUsername());
        assertEquals(recoveryMail, userDetails.getUserDetails().getRecoveryMail());
        assertEquals(UserRole.USER, userDetails.getUserDetails().getRole());
        assertTrue(userDetails.getUserDetails().getCredentials().getPassword().isEmpty());
        assertEquals(HttpStatus.OK, userDetails.getHttpStatus());
    }


    @Test
    public void getUserDetailsOverAMQPFailNotExistingUser() throws
            IOException {
        assertFalse(userRepository.exists(username));
        //ask for not existing user
        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsBytes(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                null, null
        )), new MessageProperties())).getBody();

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        assertEquals(HttpStatus.BAD_REQUEST, userDetails.getHttpStatus());
    }

    @Test
    public void getUserDetailsOverAMQPFailWrongPassword() throws
            IOException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER, AccountStatus.NEW);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsBytes(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, wrongPassword),
                null, OperationType.READ
        )), new MessageProperties())).getBody();

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        assertEquals(HttpStatus.UNAUTHORIZED, userDetails.getHttpStatus());
        assertTrue(userDetails.getUserDetails().getRecoveryMail().isEmpty());
        assertEquals(UserRole.NULL, userDetails.getUserDetails().getRole());
        assertTrue(userDetails.getUserDetails().getCredentials().getUsername().isEmpty());
        assertTrue(userDetails.getUserDetails().getCredentials().getPassword().isEmpty());
    }

    @Test
    public void getUserDetailsOverAMQPFailRequestWithoutUserCredentials() throws
            IOException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER, AccountStatus.NEW);
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
    public void getUserDetailsOverAMQPFailIncorrectAdminCredentials() throws
            IOException {
        // wrong Admin password
        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, wrongPassword), new Credentials(username, password),
                null, null
        )).getBytes(), new MessageProperties())).getBody();

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);
        assertEquals(HttpStatus.FORBIDDEN, userDetails.getHttpStatus());

        //wrong Admin username
        response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(username, AAMOwnerPassword), new Credentials(username, password),
                null, null
        )).getBytes(), new MessageProperties())).getBody();

        userDetails = mapper.readValue(response,
                UserDetailsResponse.class);
        assertEquals(HttpStatus.FORBIDDEN, userDetails.getHttpStatus());
    }

    @Test
    public void sendMessageOverAMQPFailWrongMessage() throws
            IOException {
        String wrongmessage = "{wrong message json}";
        // send incorrect message over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(getUserDetailsQueue, new Message(mapper.writeValueAsBytes
                (wrongmessage), new MessageProperties())).getBody();
        ErrorResponseContainer sspRegistrationOverAMQPResponse = mapper.readValue(response,
                ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), sspRegistrationOverAMQPResponse.getErrorCode());
    }
}
