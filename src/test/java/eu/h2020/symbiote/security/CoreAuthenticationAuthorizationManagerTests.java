package eu.h2020.symbiote.security;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.ExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.json.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.codehaus.jettison.json.JSONException;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for Core AAM deployment scenarios.
 */
@TestPropertySource("/core.properties")
public class CoreAuthenticationAuthorizationManagerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CoreAuthenticationAuthorizationManagerTests.class);

    private final String coreAppUsername = "testCoreAppUsername";
    private final String coreAppPassword = "testCoreAppPassword";
    private final String recoveryMail = "null@dev.null";
    private final String federatedOAuthId = "federatedOAuthId";
    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformAAMURL = "https://platform1.eu/AAM/";

    UserRegistrationRequest userRegistrationRequest;
    private RpcClient appRegistrationClient;
    private UserDetails userDetails;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        appRegistrationClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                appRegistrationRequestQueue, 5000);

        userDetails = new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.APPLICATION);
        userRegistrationRequest = new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), userDetails);
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationFailureUnauthorized() throws IOException, TimeoutException {

        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue the same app registration over AMQP expecting with wrong AAMOwnerUsername
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername + "wrongString", AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail,UserRole.APPLICATION))).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(coreAppUsername));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("UNAUTHORIZED_APP_REGISTRATION", errorResponse.getErrorMessage());

        // issue the same app registration over AMQP expecting with wrong AAMOwnerPasword
        response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword + "wrongString"), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail,UserRole.APPLICATION))).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(coreAppUsername));

        // verify error response
        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("UNAUTHORIZED_APP_REGISTRATION", errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationFailureWrongUserRole() throws IOException, TimeoutException {

        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue the same app registration over AMQP expecting with wrong PlatformOwner UserRole
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail,UserRole.PLATFORM_OWNER))).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(coreAppUsername));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("USER_REGISTRATION_ERROR", errorResponse.getErrorMessage());

        // issue the same app registration over AMQP expecting with wrong Null UserRole
        response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail,UserRole.NULL))).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(coreAppUsername));

        // verify error response
        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("USER_REGISTRATION_ERROR", errorResponse.getErrorMessage());
    }



    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationFailureUsernameExists() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue app registration over AMQP
        appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail,UserRole.APPLICATION))).getBytes());


        // verify that app really is in repository
        assertNotNull(userRepository.findOne(coreAppUsername));

        // issue the same app registration over AMQP expecting refusal
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail,UserRole.APPLICATION))).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("USER_ALREADY_REGISTERED", errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationFailureMissingAppUsername() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue app registration over AMQP with missing username
        userDetails.getCredentials().setUsername("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(userRegistrationRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("ERR_MISSING_ARGUMENTS", errorResponse.getErrorMessage());
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationFailureMissingAppPassword() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue app registration over AMQP with missing password
        userDetails.getCredentials().setPassword("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(userRegistrationRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("ERR_MISSING_ARGUMENTS", errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationFailureMissingAppFederatedId() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));


        // issue app registration over AMQP with missing federatedId
        userDetails.setFederatedID("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(userRegistrationRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("ERR_MISSING_ARGUMENTS", errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationFailureMissingRecoveryMail() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue app registration over AMQP with missing recovery mail
        userDetails.setRecoveryMail("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(userRegistrationRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("ERR_MISSING_ARGUMENTS", errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationSuccess() throws IOException, TimeoutException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException, MissingArgumentsException, KeyStoreException,
            InvalidAlgorithmParameterException, NoSuchProviderException, OperatorCreationException,
            WrongCredentialsException, ExistingUserException {

        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue app registration over AMQP
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail,UserRole.APPLICATION))).getBytes());

        UserRegistrationResponse appRegistrationResponse = mapper.readValue(response,
                UserRegistrationResponse.class);

        log.info("Test Client received this key and certificate " + appRegistrationResponse.toJson());

        // verify that app really is in repository
        User registeredUser = userRepository.findOne(coreAppUsername);
        assertNotNull(registeredUser);
        assertEquals(UserRole.APPLICATION, registeredUser.getRole());

        // verify that the server returns certificate & privateKey
        assertNotNull(appRegistrationResponse.getPemCertificate());
        assertNotNull(appRegistrationResponse.getPemPrivateKey());
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    @Ignore("Not yet implemented")
    public void applicationLoginSuccessAndIssuesRelevantTokenTypeWithoutPOAttributes() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new Credentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(tokenHeaderName));
        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(tokenHeaderName));
            // for tests the token type should be set to NULL
            assertEquals(IssuingAuthorityType.NULL, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));
        } catch (MalformedJWTException | JSONException e) {
            e.printStackTrace();
        }
    }


    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void platformRegistrationWithPreferredPlatformIdSuccess() throws IOException, TimeoutException {
        // TODO implement similar to app registration
        // check no platform in repository
        // check no PO in repository
        // register platform with PO
        // check response certs,key if platform id matches preferred and if public cert is CA type!!!
        // check if platform in repo
        // check if PO in repo
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformRegistrationRequestQueue, 5000);
        byte[] response;

        PlatformRegistrationRequest platformRegistrationRequest = new PlatformRegistrationRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new
                Credentials("Username", "Password"), federatedOAuthId, recoveryMail, UserRole.PLATFORM_OWNER),
                platformAAMURL, preferredPlatformId);

        response = client.primitiveCall(mapper.writeValueAsString(platformRegistrationRequest).getBytes());
        PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
                PlatformRegistrationResponse.class);

        log.info("Test Client received this key and certificate " + platformRegistrationResponse);

        assertNotEquals(platformRegistrationResponse.getPemCertificate(), null);
        assertNotEquals(platformRegistrationResponse.getPemPrivateKey(), null);
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void platformRegistrationWithGeneratedPlatformIdSuccess() throws IOException, TimeoutException {
        // TODO implement similar to app registration
        // check no platform in repository
        // check no PO in repository
        // register platform with PO
        // check response certs,key,id and if public cert is CA type!!!
        // check if platform in repo
        // check if PO in repo
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    @Ignore("Not yet implemented")
    public void platformOwnerLoginSuccessAndIssuesRelevantTokenTypeWithPOAttributes() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new Credentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(tokenHeaderName));
        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(tokenHeaderName));
            // for tests the token type should be set to NULL
            assertEquals(IssuingAuthorityType.NULL, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));
        } catch (MalformedJWTException | JSONException e) {
            e.printStackTrace();
        }
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void platformRegistrationFailureUnauthorized() throws IOException, TimeoutException {
        // TODO implement
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void platformRegistrationFailureMissingArguments() throws IOException, TimeoutException {
        // TODO implement
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void platformRegistrationFailurePOUsernameExists() throws IOException, TimeoutException {
        // TODO implement similar to existing app registration
        // clear platforms & users repo
        // register platform
        // attempt to register it again with different preferred platform ID
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                    platformRegistrationRequestQueue, 5000);
            byte[] response;
            /*
            response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new
            Credentials("Username","Password"), "federatedID",
                "recoveryMail","platformIPAurl")).getBytes());
            PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
            PlatformRegistrationResponse.class);
            */
        } catch (Exception e) {
            /*
            assertEquals(new ExistingPlatformException().getErrorMessage(), e.getClass());
            */
        }

    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void platformRegistrationFailurePreferredPlatformIdExists() throws IOException, TimeoutException {
        // TODO implement similar to existing app registration
        // clear platforms & users repo
        // register platform
        // attempt to register it again with different username
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                    platformRegistrationRequestQueue, 5000);
            byte[] response;
            /*
            response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new
            Credentials("Username","Password"),"federatedID",
                "preferredPlatformID","recoveryMail","platformIPAurl")).getBytes());
            PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
            PlatformRegistrationResponse.class);
            */
        } catch (Exception e) {
            /*
            assertEquals(new ExistingPlatformException().getErrorMessage(), e.getClass());
            */
        }

    }


}