package eu.h2020.symbiote.security;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.Platform;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.*;
import eu.h2020.symbiote.security.commons.json.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.commons.jwt.attributes.CoreAttributes;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.codehaus.jettison.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Map;
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
    private final String platformOwnerUsername = "testPlatformOwnerUsername";
    private final String platformOwnerPassword = "testPlatormOwnerPassword";

    private UserRegistrationRequest appUserRegistrationRequest;
    private RpcClient appRegistrationClient;
    private UserDetails appUserDetails;

    private RpcClient platformRegistrationClient;
    private UserDetails platformOwnerUserDetails;
    private PlatformRegistrationRequest platformRegistrationRequest;

    @Autowired
    private PlatformRepository platformRepository;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // db cleanup
        platformRepository.deleteAll();

        // application registration useful
        appRegistrationClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                appRegistrationRequestQueue, 5000);
        appUserDetails = new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.APPLICATION);
        appUserRegistrationRequest = new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), appUserDetails);

        // platform registration useful
        platformRegistrationClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformRegistrationRequestQueue, 5000);
        platformOwnerUserDetails = new UserDetails(new Credentials(
                platformOwnerUsername, platformOwnerPassword), federatedOAuthId, recoveryMail, UserRole.PLATFORM_OWNER);
        platformRegistrationRequest = new PlatformRegistrationRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword), platformOwnerUserDetails, platformAAMURL, preferredPlatformId);
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

        // issue the app registration over AMQP expecting with wrong AAMOwnerUsername
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername + "wrongString", AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.APPLICATION))).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(coreAppUsername));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UnauthorizedRegistrationException.errorMessage, errorResponse.getErrorMessage());

        // issue the same app registration over AMQP expecting with wrong AAMOwnerPassword
        response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword + "wrongString"), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.APPLICATION))).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(coreAppUsername));

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
    public void applicationRegistrationFailureWrongUserRole() throws IOException, TimeoutException {

        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue the same app registration over AMQP expecting with wrong PlatformOwner UserRole
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.PLATFORM_OWNER))).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(coreAppUsername));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UserRegistrationException.errorMessage, errorResponse.getErrorMessage());

        // issue the same app registration over AMQP expecting with wrong Null UserRole
        response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.NULL))).getBytes());

        // verify that our app was not registered in the repository
        assertNull(userRepository.findOne(coreAppUsername));

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
    public void applicationRegistrationFailureUsernameExists() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue app registration over AMQP
        appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.APPLICATION))).getBytes());


        // verify that app really is in repository
        assertNotNull(userRepository.findOne(coreAppUsername));

        // issue the same app registration over AMQP expecting refusal
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.APPLICATION))).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(ExistingUserException.errorMessage, errorResponse.getErrorMessage());
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
        appUserDetails.getCredentials().setUsername("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserRegistrationRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
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
        appUserDetails.getCredentials().setPassword("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserRegistrationRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
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
        appUserDetails.setFederatedID("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserRegistrationRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
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
        appUserDetails.setRecoveryMail("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserRegistrationRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
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
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.APPLICATION))).getBytes());

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

        // TODO verify that released certificate has no CA property
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void applicationLoginSuccessAndIssuesCoreTokenWithoutPOAttributes() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new Credentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(tokenHeaderName));
        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(tokenHeaderName));
            assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

            // verify that this JWT contains attributes relevant for application role
            Map<String, String> attributes = claimsFromToken.getAtt();
            assertEquals(UserRole.APPLICATION.toString(), attributes.get(CoreAttributes.ROLE.toString()));

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
    public void platformRegistrationWithPreferredPlatformIdSuccess() throws IOException, TimeoutException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        byte[] response = platformRegistrationClient.primitiveCall(mapper.writeValueAsString(platformRegistrationRequest).getBytes());
        PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
                PlatformRegistrationResponse.class);

        // verify that the server returns certificate & privateKey
        assertNotNull(platformRegistrationResponse.getPemCertificate());
        assertNotNull(platformRegistrationResponse.getPemPrivateKey());

        // TODO verify that released certificate has no CA property

        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationResponse.getPlatformId());

        // verify that PO is in repository (as PO!)
        User registeredPlatformOwner = userRepository.findOne(platformOwnerUsername);
        assertNotNull(registeredPlatformOwner);
        assertEquals(UserRole.PLATFORM_OWNER, registeredPlatformOwner.getRole());

        // verify that platform with preferred id is in repository and is tied with the given PO
        Platform registeredPlatform = platformRepository.findOne(preferredPlatformId);
        assertNotNull(registeredPlatform);
        assertEquals(platformOwnerUsername, registeredPlatform.getPlatformOwner().getUsername());

        // verify that platform oriented fields are properly stored
        assertEquals(platformAAMURL, registeredPlatform.getPlatformAAMURL());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationWithGeneratedPlatformIdSuccess() throws IOException, TimeoutException {
        // verify that our platformOwner is not in repository
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without preferred platform identifier
        platformRegistrationRequest.setPlatformId("");
        byte[] response = platformRegistrationClient.primitiveCall(mapper.writeValueAsString(platformRegistrationRequest).getBytes());
        PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
                PlatformRegistrationResponse.class);

        // verify that the server returns certificate & privateKey
        assertNotNull(platformRegistrationResponse.getPemCertificate());
        assertNotNull(platformRegistrationResponse.getPemPrivateKey());

        // TODO verify that released certificate has no CA property

        // verified that we received a generated platformId
        String generatedPlatformId = platformRegistrationResponse.getPlatformId();
        assertNotNull(generatedPlatformId);

        // verify that PO is in repository (as PO!)
        User registeredPlatformOwner = userRepository.findOne(platformOwnerUsername);
        assertNotNull(registeredPlatformOwner);
        assertEquals(UserRole.PLATFORM_OWNER, registeredPlatformOwner.getRole());

        // verify that platform with the generated id is in repository and is tied with the given PO
        Platform registeredPlatform = platformRepository.findOne(generatedPlatformId);
        assertNotNull(registeredPlatform);
        assertEquals(platformOwnerUsername, registeredPlatform.getPlatformOwner().getUsername());

        // verify that platform oriented fields are properly stored
        assertEquals(platformAAMURL, registeredPlatform.getPlatformAAMURL());
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void platformOwnerLoginSuccessAndIssuesRelevantTokenTypeWithPOAttributes() throws IOException, TimeoutException, MalformedJWTException, JSONException, CertificateException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationClient.primitiveCall(mapper.writeValueAsString(platformRegistrationRequest).getBytes());

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new Credentials(platformOwnerUsername, platformOwnerPassword), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        //verify that JWT was issued for user
        assertNotNull(headers.getFirst(tokenHeaderName));

        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(tokenHeaderName));

        //verify that JWT is of type Core as was released by a CoreAAM
        assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

        // verify that this JWT contains attributes relevant for platform owner
        Map<String, String> attributes = claimsFromToken.getAtt();
        // PO role
        assertEquals(UserRole.PLATFORM_OWNER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        // owned platform identifier
        assertEquals(preferredPlatformId, attributes.get(CoreAttributes.OWNED_PLATFORM.toString()));
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationFailureUnauthorized() throws IOException, TimeoutException {

        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP expecting with wrong AAMOwnerUsername
        platformRegistrationRequest.getAAMOwnerCredentials().setUsername(AAMOwnerUsername + "somethingWrong");
        byte[] response = platformRegistrationClient.primitiveCall(mapper.writeValueAsString(platformRegistrationRequest).getBytes());

        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UnauthorizedRegistrationException.errorMessage, errorResponse.getErrorMessage());

        // issue platform registration over AMQP expecting with wrong AAMOwnerUsername
        platformRegistrationRequest.getAAMOwnerCredentials().setUsername(AAMOwnerUsername);
        platformRegistrationRequest.getAAMOwnerCredentials().setPassword(AAMOwnerPassword + "somethingWrong");
        response = platformRegistrationClient.primitiveCall(mapper.writeValueAsString(platformRegistrationRequest).getBytes());

        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // verify error response
        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UnauthorizedRegistrationException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationFailureMissingArguments() throws IOException, TimeoutException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without required Platform's AAM URL
        platformRegistrationRequest.setPlatformAAMURL("");
        byte[] response = platformRegistrationClient.primitiveCall(mapper.writeValueAsString(platformRegistrationRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationFailurePOUsernameExists() throws IOException, TimeoutException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        byte[] response = platformRegistrationClient.primitiveCall(mapper.writeValueAsString(platformRegistrationRequest).getBytes());

        // verify that platform with preferred id is in repository and is tied with the given PO
        PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
                PlatformRegistrationResponse.class);
        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        // issue registration request with different preferred platform identifier but for the same PO
        platformRegistrationRequest.setPlatformId(preferredPlatformId + "different");
        response = platformRegistrationClient.primitiveCall(mapper.writeValueAsString(platformRegistrationRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(ExistingUserException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationFailurePreferredPlatformIdExists() throws IOException, TimeoutException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        byte[] response = platformRegistrationClient.primitiveCall(mapper.writeValueAsString(platformRegistrationRequest).getBytes());

        // verify that platform with preferred id is in repository and is tied with the given PO
        PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
                PlatformRegistrationResponse.class);
        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        // issue registration request with the same preferred platform identifier but different PO
        platformRegistrationRequest.getPlatformOwnerDetails().getCredentials().setUsername(platformOwnerUsername + "differentOne");
        response = platformRegistrationClient.primitiveCall(mapper.writeValueAsString(platformRegistrationRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(ExistingPlatformException.errorMessage, errorResponse.getErrorMessage());
    }


}