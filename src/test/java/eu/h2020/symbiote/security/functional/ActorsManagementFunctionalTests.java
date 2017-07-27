package eu.h2020.symbiote.security.functional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.RegistrationStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.interfaces.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.interfaces.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class ActorsManagementFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(OtherListenersFunctionalTests.class);
    private final String recoveryMail = "null@dev.null";
    private final String federatedOAuthId = "federatedOAuthId";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    private UserManagementRequest appUserManagementRequest;
    private RpcClient appRegistrationClient;
    private UserDetails appUserDetails;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // user registration useful
        appRegistrationClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                userRegistrationRequestQueue, 5000);
        appUserDetails = new UserDetails(new Credentials(
                username, password), federatedOAuthId, recoveryMail, UserRole.USER);
        appUserManagementRequest = new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), appUserDetails);
    }

    @Test
    public void userRegistrationOverAMQPFailureUnauthorized() throws IOException, TimeoutException {

        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));

        // issue the app registration over AMQP expecting with wrong AAMOwnerUsername
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername + "wrongString", AAMOwnerPassword), new UserDetails(new Credentials(
                username, password), federatedOAuthId, recoveryMail, UserRole.USER))).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(username));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UnauthorizedRegistrationException.errorMessage, errorResponse.getErrorMessage());

        // issue the same app registration over AMQP expecting with wrong AAMOwnerPassword
        response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword + "wrongString"), new UserDetails(new Credentials(
                username, password), federatedOAuthId, recoveryMail, UserRole.USER))).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(username));

        // verify error response
        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UnauthorizedRegistrationException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPFailureWrongUserRole() throws IOException, TimeoutException {

        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));

        // issue the same app registration over AMQP expecting with wrong PlatformOwner UserRole
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                username, password), federatedOAuthId, recoveryMail, UserRole.PLATFORM_OWNER)))
                .getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(username));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UserRegistrationException.errorMessage, errorResponse.getErrorMessage());

        // issue the same app registration over AMQP expecting with wrong Null UserRole
        response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                username, password), federatedOAuthId, recoveryMail, UserRole.NULL))).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(username));

        // verify error response
        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UserRegistrationException.errorMessage, errorResponse.getErrorMessage());
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPFailureUsernameExists() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));

        // issue app registration over AMQP
        appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                username, password), federatedOAuthId, recoveryMail, UserRole.USER))).getBytes());


        // verify that app really is in repository
        assertNotNull(userRepository.findOne(username));

        // issue the same app registration over AMQP expecting refusal
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                username, password), federatedOAuthId, recoveryMail, UserRole.USER))).getBytes());

        RegistrationStatus errorResponse = mapper.readValue(response, RegistrationStatus.class);
        assertEquals(RegistrationStatus.USERNAME_EXISTS, errorResponse);
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPFailureMissingAppUsername() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));

        // issue app registration over AMQP with missing username
        appUserDetails.getCredentials().setUsername("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserManagementRequest)
                .getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPFailureMissingAppPassword() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));

        // issue app registration over AMQP with missing password
        appUserDetails.getCredentials().setPassword("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserManagementRequest)
                .getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPFailureMissingAppForeignId() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));


        // issue app registration over AMQP with missing foreignId
        appUserDetails.setFederatedID("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserManagementRequest)
                .getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPFailureMissingRecoveryMail() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));

        // issue app registration over AMQP with missing recovery mail
        appUserDetails.setRecoveryMail("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserManagementRequest)
                .getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPSuccess() throws IOException, TimeoutException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException, MissingArgumentsException, KeyStoreException,
            InvalidAlgorithmParameterException, NoSuchProviderException, OperatorCreationException,
            WrongCredentialsException, ExistingUserException {

        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));

        // issue app registration over AMQP
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                username, password), federatedOAuthId, recoveryMail, UserRole.USER))).getBytes());

        RegistrationStatus appRegistrationResponse = mapper.readValue(response,
                RegistrationStatus.class);
        assertEquals(appRegistrationResponse, RegistrationStatus.OK);

        // verify that app really is in repository
        User registeredUser = userRepository.findOne(username);
        assertNotNull(registeredUser);
        assertEquals(UserRole.USER, registeredUser.getRole());

        // verify that the user has no certs
        assertTrue(registeredUser.getClientCertificates().isEmpty());
    }

    @Test
    public void userRegistrationOverRESTSuccess() throws JsonProcessingException {
        String testAppUsername = "NewApplication";
        UserManagementRequest request = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new UserDetails(new Credentials(testAppUsername, "NewPassword"), federatedOAuthId, recoveryMail, UserRole.USER));
        // verify that app is not in the repository
        User registeredUser = userRepository.findOne(testAppUsername);
        assertNull(registeredUser);

        ResponseEntity<RegistrationStatus> response = restTemplate.postForEntity(serverAddress +
                registrationUri, request, RegistrationStatus.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        // verify that app really is in repository
        registeredUser = userRepository.findOne(testAppUsername);
        assertNotNull(registeredUser);
        assertEquals(UserRole.USER, registeredUser.getRole());

        // verify that the user has no certs
        assertTrue(registeredUser.getClientCertificates().isEmpty());
    }

    /**
     * Feature: PAAM - 2 (Application Registration)
     * Interface: PAAM - 3a
     * CommunicationType REST
     */
    @Test
    public void userUnregistrationOverRESTSuccess() throws JsonProcessingException {
        UserManagementRequest request = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new UserDetails(new Credentials(username, password),
                        federatedOAuthId, recoveryMail, UserRole.USER));
        // prepare the user in db
        userRepository.save(new User(username, passwordEncoder.encode(password), recoveryMail, new HashMap<>(), UserRole.USER, new ArrayList<>()));

        ResponseEntity<Void> response = restTemplate.postForEntity(serverAddress + unregistrationUri, request,
                Void.class);
        // check that it succeed
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertFalse(userRepository.exists(username));
    }

}
