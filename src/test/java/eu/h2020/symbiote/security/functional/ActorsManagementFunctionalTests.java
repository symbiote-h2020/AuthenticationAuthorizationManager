package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class ActorsManagementFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(OtherListenersFunctionalTests.class);
    private final String federatedOAuthId = "federatedOAuthId";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    @Value("${rabbit.queue.get.user.details}")
    private String getUserDetailsQueue;
    @Value("${rabbit.routingKey.get.user.details}")
    private String getUserDetailsRoutingKey;
    private UserManagementRequest appUserRegistrationRequest;
    private UserManagementRequest appUserUpdateRequest;
    private RpcClient appManagementClient;
    private UserDetails appUserDetails;
    private RpcClient getUserDetailsClient;
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // user registration useful
        appManagementClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                userManagementRequestQueue, 5000);
        appUserDetails = new UserDetails(new Credentials(
                username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>());
        appUserRegistrationRequest = new UserManagementRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, password), appUserDetails, OperationType.CREATE);
        appUserUpdateRequest = new UserManagementRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, password), appUserDetails, OperationType.UPDATE);

        getUserDetailsClient = new RpcClient(rabbitManager.getConnection().createChannel(), "", getUserDetailsQueue, 5000);
    }

    @Test
    public void userRegistrationOverAMQPFailureUnauthorized() throws IOException, TimeoutException {

        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));

        // issue the app registration over AMQP expecting with wrong AAMOwnerUsername
        byte[] response = appManagementClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername + "wrongString", AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(username));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UserManagementException.errorMessage, errorResponse.getErrorMessage());

        // issue the same app registration over AMQP expecting with wrong AAMOwnerPassword
        response = appManagementClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword + "wrongString"), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(username));

        // verify error response
        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UserManagementException.errorMessage, errorResponse.getErrorMessage());
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

        // issue the same app registration over AMQP expecting with wrong UserRole
        byte[] response = appManagementClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.NULL, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(username));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UserManagementException.errorMessage, errorResponse.getErrorMessage());
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
        appManagementClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());


        // verify that app really is in repository
        assertNotNull(userRepository.findOne(username));

        // issue the same app registration over AMQP expecting refusal
        byte[] response = appManagementClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());

        ManagementStatus errorResponse = mapper.readValue(response, ManagementStatus.class);
        assertEquals(ManagementStatus.USERNAME_EXISTS, errorResponse);
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
        byte[] response = appManagementClient.primitiveCall(mapper.writeValueAsString(appUserRegistrationRequest)
                .getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(InvalidArgumentsException.errorMessage, errorResponse.getErrorMessage());
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
        byte[] response = appManagementClient.primitiveCall(mapper.writeValueAsString(appUserRegistrationRequest)
                .getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(InvalidArgumentsException.errorMessage, errorResponse.getErrorMessage());
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
        byte[] response = appManagementClient.primitiveCall(mapper.writeValueAsString(appUserRegistrationRequest)
                .getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(InvalidArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPSuccess() throws IOException, TimeoutException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException, InvalidArgumentsException, KeyStoreException,
            InvalidAlgorithmParameterException, NoSuchProviderException, OperatorCreationException,
            WrongCredentialsException {

        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));
        Map<String, String> attributesMap = new HashMap<>();
        attributesMap.put("testKey", "testAttribute");
        // issue app registration over AMQP
        byte[] response = appManagementClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, attributesMap, new HashMap<>()),
                OperationType.CREATE)).getBytes());

        ManagementStatus appRegistrationResponse = mapper.readValue(response,
                ManagementStatus.class);
        assertEquals(appRegistrationResponse, ManagementStatus.OK);

        // verify that app really is in repository
        User registeredUser = userRepository.findOne(username);
        assertNotNull(registeredUser);
        assertEquals(UserRole.USER, registeredUser.getRole());
        assertEquals(attributesMap.get("testKey"), registeredUser.getAttributes().get("testKey"));
        // verify that the user has no certs
        assertTrue(registeredUser.getClientCertificates().isEmpty());
    }

    @Test
    public void userUpdateOverAMQPSuccess() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));
        // issue app registration over AMQP
        byte[] response = appManagementClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());
        ManagementStatus appRegistrationResponse = mapper.readValue(response, ManagementStatus.class);
        assertEquals(appRegistrationResponse, ManagementStatus.OK);

        //creating new attributes map
        Map<String, String> attributes = new HashMap<>();
        attributes.put("key", "attribute");

        appUserUpdateRequest.getUserDetails().setRecoveryMail(recoveryMail + "differentOne");
        appUserUpdateRequest.getUserDetails().getCredentials().setPassword(password + "differentOne");
        byte[] response2 = appManagementClient.primitiveCall(mapper.writeValueAsString(appUserUpdateRequest).getBytes());
        ManagementStatus appRegistrationResponse2 = mapper.readValue(response2, ManagementStatus.class);
        assertEquals(ManagementStatus.OK, appRegistrationResponse2);
        User user = userRepository.findOne(username);
        //attributes map should not be updated during UPDATE operationType
        assertFalse(user.getAttributes().containsValue("attribute"));
    }


    @Test
    public void userUpdateOverAMQFailureWrongPassword() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));

        // issue app registration over AMQP
        byte[] response = appManagementClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());
        ManagementStatus appRegistrationResponse = mapper.readValue(response, ManagementStatus.class);
        assertEquals(appRegistrationResponse, ManagementStatus.OK);

        appUserUpdateRequest.getUserCredentials().setPassword(wrongpassword);
        byte[] response2 = appManagementClient.primitiveCall(mapper.writeValueAsString(appUserUpdateRequest).getBytes());
        ErrorResponseContainer errorResponse = mapper.readValue(response2, ErrorResponseContainer.class);
        assertEquals(UserManagementException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void platformOwnerRegistrationOverAMQPSuccess() throws IOException, TimeoutException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException, InvalidArgumentsException, KeyStoreException,
            InvalidAlgorithmParameterException, NoSuchProviderException, OperatorCreationException,
            WrongCredentialsException {

        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));

        // issue app registration over AMQP
        byte[] response = appManagementClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail,
                        UserRole.PLATFORM_OWNER, new HashMap<>(), new HashMap<>()), OperationType.CREATE)).getBytes());

        ManagementStatus platformOwnerRegistrationResponse = mapper.readValue(response,
                ManagementStatus.class);
        assertEquals(platformOwnerRegistrationResponse, ManagementStatus.OK);

        // verify that app really is in repository
        User registeredUser = userRepository.findOne(username);
        assertNotNull(registeredUser);
        assertEquals(UserRole.PLATFORM_OWNER, registeredUser.getRole());
        assertNull(platformRepository.findByPlatformOwner(registeredUser));
        // verify that the user has no certs
        assertTrue(registeredUser.getClientCertificates().isEmpty());
    }

    @Test
    public void UsersManagementCreationSuccess() throws AAMException {
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), "federatedId",
                        "nullMail", UserRole.USER, new HashMap<>(), new HashMap<>()), OperationType.CREATE);
        ManagementStatus managementStatus = AAMClient.manage(userManagementRequest);
        assertNotNull(managementStatus);
    }

    @Test(expected = AAMException.class)
    public void UsersManagementCreationFailureWithIncorrectRequest() throws AAMException {
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, wrongpassword), new Credentials(username, wrongpassword),
                new UserDetails(new Credentials(username, wrongpassword), "federatedId",
                        "", UserRole.PLATFORM_OWNER, new HashMap<>(), new HashMap<>()), OperationType.CREATE);
        AAMClient.manage(userManagementRequest);
    }

    @Test
    public void requestUserDetailsOverAMQPSuccess() throws IOException, TimeoutException {
        //  Registering user in database
        User User = new User();
        User.setUsername(username);
        User.setPasswordEncrypted(passwordEncoder.encode(password));
        User.setRecoveryMail(recoveryMail);
        User.setRole(UserRole.USER);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = getUserDetailsClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                null, null
        )).getBytes());

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        log.info("Retrieved username is: " + userDetails.getUserDetails().getCredentials().getUsername());
        assertEquals(username, userDetails.getUserDetails().getCredentials().getUsername());
        assertEquals(HttpStatus.OK, userDetails.getHttpStatus());
    }

    @Test
    public void requestUserDetailsOverAMQPFailsForNotExistingUser() throws IOException, TimeoutException {
        //  Registering user in database
        User User = new User();
        User.setUsername(username);
        User.setPasswordEncrypted(passwordEncoder.encode(password));
        User.setRecoveryMail(recoveryMail);
        User.setRole(UserRole.USER);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = getUserDetailsClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials("NotExistingUser", "Password"),
                null, null
        )).getBytes());

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        assertEquals(HttpStatus.BAD_REQUEST, userDetails.getHttpStatus());
    }

    @Test
    public void requestUserDetailsOverAMQPFailsForWrongPassword() throws IOException, TimeoutException {
        //  Registering user in database
        User User = new User();
        User.setUsername(username);
        User.setPasswordEncrypted(passwordEncoder.encode(password));
        User.setRecoveryMail(recoveryMail);
        User.setRole(UserRole.USER);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = getUserDetailsClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, "WrongPassword"),
                null, null
        )).getBytes());

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);

        assertEquals(HttpStatus.UNAUTHORIZED, userDetails.getHttpStatus());
    }

    @Test
    public void requestUserDetailsOverAMQPFailsForRequestWithoutUserCredentials() throws IOException, TimeoutException {
        //  Registering user in database
        User User = new User();
        User.setUsername(username);
        User.setPasswordEncrypted(passwordEncoder.encode(password));
        User.setRecoveryMail(recoveryMail);
        User.setRole(UserRole.USER);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        byte[] response = getUserDetailsClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), null,
                null, null
        )).getBytes());

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);
        assertEquals(HttpStatus.UNAUTHORIZED, userDetails.getHttpStatus());
    }

    @Test
    public void getUserDetailsFailsForIncorrectAdminPassword() throws IOException, TimeoutException {

        byte[] response = getUserDetailsClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, "wrongPassword"), new Credentials(username, password),
                null, null
        )).getBytes());

        UserDetailsResponse userDetails = mapper.readValue(response,
                UserDetailsResponse.class);
        assertEquals(HttpStatus.FORBIDDEN, userDetails.getHttpStatus());
    }
}
