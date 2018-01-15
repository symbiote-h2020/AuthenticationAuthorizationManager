package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.BlockedUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class UsersManagementFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(OtherListenersFunctionalTests.class);
    private final String federatedOAuthId = "federatedOAuthId";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    protected String platformAAMSuffixAtInterWorkingInterface;
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    protected String coreInterfaceAddress;
    @Value("${rabbit.queue.get.user.details}")
    private String getUserDetailsQueue;
    @Value("${rabbit.routingKey.get.user.details}")
    private String getUserDetailsRoutingKey;
    private UserManagementRequest appUserRegistrationRequest;
    private UserManagementRequest appUserUpdateRequest;
    private UserDetails appUserDetails;
    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Override
    @Before
    public void setUp() throws
            Exception {
        super.setUp();

        // user registration useful
        appUserDetails = new UserDetails(new Credentials(
                username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>());
        appUserRegistrationRequest = new UserManagementRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, password), appUserDetails, OperationType.CREATE);
        appUserUpdateRequest = new UserManagementRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, password), appUserDetails, OperationType.UPDATE);
        // verify that our app is not in repository
        assertNull(userRepository.findOne(username));

    }

    @Test
    public void userRegistrationOverAMQPFailureUnauthorized() throws
            IOException {

        // issue the app registration over AMQP expecting with wrong AAMOwnerUsername
        Object response = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername + "wrongString", AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(username));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.convertValue(response, ErrorResponseContainer.class);
        assertEquals(UserManagementException.errorMessage, errorResponse.getErrorMessage());

        // issue the same app registration over AMQP expecting with wrong AAMOwnerPassword
        response = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword + "wrongString"), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(username));

        // verify error response
        errorResponse = mapper.convertValue(response, ErrorResponseContainer.class);
        assertEquals(UserManagementException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPFailureWrongUserRole() throws
            IOException {

        // issue the same app registration over AMQP expecting with wrong UserRole
        Object response = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.NULL, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(username));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.convertValue(response, ErrorResponseContainer.class);
        assertEquals(UserManagementException.errorMessage, errorResponse.getErrorMessage());
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPFailureUsernameExists() throws
            IOException {

        // issue app registration over AMQP
        rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());


        // verify that app really is in repository
        assertNotNull(userRepository.findOne(username));

        // issue the same app registration over AMQP expecting refusal
        Object response = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());

        ManagementStatus errorResponse = mapper.convertValue(response, ManagementStatus.class);
        assertEquals(ManagementStatus.USERNAME_EXISTS, errorResponse);
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPFailureMissingAppUsername() throws
            IOException {

        // issue app registration over AMQP with missing username
        appUserDetails.getCredentials().setUsername("");
        Object response = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(appUserRegistrationRequest)
                .getBytes());

        ErrorResponseContainer errorResponse = mapper.convertValue(response, ErrorResponseContainer.class);
        assertEquals(InvalidArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPFailureMissingAppPassword() throws
            IOException {

        // issue app registration over AMQP with missing password
        appUserDetails.getCredentials().setPassword("");
        Object response = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(appUserRegistrationRequest)
                .getBytes());

        ErrorResponseContainer errorResponse = mapper.convertValue(response, ErrorResponseContainer.class);
        assertEquals(InvalidArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPFailureMissingRecoveryMail() throws
            IOException {

        // issue app registration over AMQP with missing recovery mail
        appUserDetails.setRecoveryMail("");
        Object response = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(appUserRegistrationRequest)
                .getBytes());

        ErrorResponseContainer errorResponse = mapper.convertValue(response, ErrorResponseContainer.class);
        assertEquals(InvalidArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void userRegistrationOverAMQPSuccess() throws
            IOException {

        Map<String, String> attributesMap = new HashMap<>();
        attributesMap.put("testKey", "testAttribute");
        // issue app registration over AMQP
        Object response = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, attributesMap, new HashMap<>()),
                OperationType.CREATE)).getBytes());

        ManagementStatus appRegistrationResponse = mapper.convertValue(response,
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
    public void userUpdateOverAMQPSuccess() throws
            IOException {

        // issue app registration over AMQP
        Object response = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());
        ManagementStatus appRegistrationResponse = mapper.convertValue(response, ManagementStatus.class);
        assertEquals(ManagementStatus.OK, appRegistrationResponse);

        //creating new attributes map
        Map<String, String> attributes = new HashMap<>();
        attributes.put("key", "attribute");

        appUserUpdateRequest.getUserDetails().setRecoveryMail(recoveryMail + "differentOne");
        appUserUpdateRequest.getUserDetails().getCredentials().setPassword(password + "differentOne");
        appUserUpdateRequest.getUserDetails().setAttributes(attributes);
        Object response2 = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(appUserUpdateRequest).getBytes());
        ManagementStatus appRegistrationResponse2 = mapper.convertValue(response2, ManagementStatus.class);
        assertEquals(ManagementStatus.OK, appRegistrationResponse2);
        User user = userRepository.findOne(username);
        //attributes map should not be updated during UPDATE operationType
        assertFalse(user.getAttributes().containsValue("attribute"));
    }


    @Test
    public void userUpdateOverAMQFailurewrongPassword() throws
            IOException {

        // issue app registration over AMQP
        Object response = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE)).getBytes());
        ManagementStatus appRegistrationResponse = mapper.convertValue(response, ManagementStatus.class);
        assertEquals(ManagementStatus.OK, appRegistrationResponse);

        appUserUpdateRequest.getUserCredentials().setPassword(wrongPassword);
        Object response2 = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(appUserUpdateRequest).getBytes());
        ErrorResponseContainer errorResponse = mapper.convertValue(response2, ErrorResponseContainer.class);
        assertEquals(UserManagementException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void platformOwnerRegistrationOverAMQPSuccess() throws
            IOException {

        // issue app registration over AMQP
        Object response = rabbitTemplate.convertSendAndReceive(userManagementRequestQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), federatedOAuthId, recoveryMail,
                        UserRole.PLATFORM_OWNER, new HashMap<>(), new HashMap<>()), OperationType.CREATE)).getBytes());

        ManagementStatus platformOwnerRegistrationResponse = mapper.convertValue(response,
                ManagementStatus.class);
        assertEquals(ManagementStatus.OK, platformOwnerRegistrationResponse);

        // verify that app really is in repository
        User registeredUser = userRepository.findOne(username);
        assertNotNull(registeredUser);
        assertEquals(UserRole.PLATFORM_OWNER, registeredUser.getRole());
        assertNull(platformRepository.findByPlatformOwner(registeredUser));
        // verify that the user has no certs
        assertTrue(registeredUser.getClientCertificates().isEmpty());
    }

    @Test
    public void userRegistrationOverRESTSuccess() throws
            AAMException {
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), "federatedId",
                        "nullMail", UserRole.USER, new HashMap<>(), new HashMap<>()), OperationType.CREATE);
        ManagementStatus managementStatus = aamClient.manageUser(userManagementRequest);
        assertNotNull(managementStatus);
    }

    @Test(expected = AAMException.class)
    public void userRegistrationOverRESTFailureWithIncorrectRequest() throws
            AAMException {
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, wrongPassword), new Credentials(username, wrongPassword),
                new UserDetails(new Credentials(username, wrongPassword), "federatedId",
                        "", UserRole.PLATFORM_OWNER, new HashMap<>(), new HashMap<>()), OperationType.CREATE);
        aamClient.manageUser(userManagementRequest);
    }

    @Test
    public void requestUserDetailsOverAMQPSuccess() throws
            IOException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        Object response = rabbitTemplate.convertSendAndReceive(getUserDetailsQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                null, null
        )).getBytes());

        UserDetailsResponse userDetails = mapper.convertValue(response,
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

        Object response = rabbitTemplate.convertSendAndReceive(getUserDetailsQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials("NotExistingUser", "Password"),
                null, null
        )).getBytes());

        UserDetailsResponse userDetails = mapper.convertValue(response,
                UserDetailsResponse.class);

        assertEquals(HttpStatus.BAD_REQUEST, userDetails.getHttpStatus());
    }

    @Test
    public void requestUserDetailsOverAMQPFailsForwrongPassword() throws
            IOException {
        //  Registering user in database
        User User = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(User);
        assertTrue(userRepository.exists(username));

        Object response = rabbitTemplate.convertSendAndReceive(getUserDetailsQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, "wrongPassword"),
                null, null
        )).getBytes());

        UserDetailsResponse userDetails = mapper.convertValue(response,
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

        Object response = rabbitTemplate.convertSendAndReceive(getUserDetailsQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), null,
                null, null
        )).getBytes());

        UserDetailsResponse userDetails = mapper.convertValue(response,
                UserDetailsResponse.class);
        assertEquals(HttpStatus.UNAUTHORIZED, userDetails.getHttpStatus());
    }

    @Test
    public void getUserDetailsFailsForIncorrectAdminPassword() throws
            IOException {

        Object response = rabbitTemplate.convertSendAndReceive(getUserDetailsQueue, mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, "wrongPassword"), new Credentials(username, password),
                null, null
        )).getBytes());

        UserDetailsResponse userDetails = mapper.convertValue(response,
                UserDetailsResponse.class);
        assertEquals(HttpStatus.FORBIDDEN, userDetails.getHttpStatus());
    }

    @Test
    public void getExistingUserOverRestSuccess() throws
            UserManagementException,
            AAMException,
            BlockedUserException {
        //  Register user in database
        User platformOwner = new User(username, passwordEncoder.encode(password), recoveryMail, new HashMap<>(), UserRole.PLATFORM_OWNER, new HashMap<>(), new HashSet<>());
        userRepository.save(platformOwner);
        //  Request user with matching credentials
        UserDetails userDetails = aamClient.getUserDetails(new Credentials(username, password));
        assertNotNull(userDetails);
    }

    @Test(expected = UserManagementException.class)
    public void getNotExistingUserOverRestFailure() throws
            UserManagementException,
            AAMException,
            BlockedUserException {
        //  Register user in database
        User platformOwner = new User(username, passwordEncoder.encode(password), recoveryMail, new HashMap<>(), UserRole.PLATFORM_OWNER, new HashMap<>(), new HashSet<>());
        userRepository.save(platformOwner);
        //  Request different user that is NOT in database
        aamClient.getUserDetails(new Credentials("NotExisting", "somePassword"));
    }

    @Test(expected = UserManagementException.class)
    public void getUserOverRestFailsForWrongPassword() throws
            UserManagementException,
            AAMException,
            BlockedUserException {
        //  Register user in database
        User platformOwner = new User(username, passwordEncoder.encode(password), recoveryMail, new HashMap<>(), UserRole.PLATFORM_OWNER, new HashMap<>(), new HashSet<>());
        userRepository.save(platformOwner);
        //  Request existing user with incorrect password
        aamClient.getUserDetails(new Credentials(username, "WrongPassword"));
    }
}
