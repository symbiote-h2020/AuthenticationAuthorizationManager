package eu.h2020.symbiote.security.integration;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AuthenticationAuthorizationManagerTests;
import eu.h2020.symbiote.security.SecurityHandler;
import eu.h2020.symbiote.security.commons.Platform;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.AAMException;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.exceptions.aam.MalformedJWTException;
import eu.h2020.symbiote.security.exceptions.aam.TokenValidationException;
import eu.h2020.symbiote.security.payloads.*;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.List;
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
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
    private final String platformOwnerUsername = "testPlatformOwnerUsername";
    private final String platformOwnerPassword = "testPlatormOwnerPassword";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    private UserRegistrationRequest appUserRegistrationRequest;
    private RpcClient appRegistrationClient;
    private UserDetails appUserDetails;
    private RpcClient platformRegistrationOverAMQPClient;
    private UserDetails platformOwnerUserDetails;
    private PlatformRegistrationRequest platformRegistrationOverAMQPRequest;
    @Autowired
    private PlatformRepository platformRepository;

    private SecurityHandler securityHandler;

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
        platformRegistrationOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformRegistrationRequestQueue, 5000);
        platformOwnerUserDetails = new UserDetails(new Credentials(
                platformOwnerUsername, platformOwnerPassword), federatedOAuthId, recoveryMail, UserRole.PLATFORM_OWNER);
        platformRegistrationOverAMQPRequest = new PlatformRegistrationRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserDetails, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId);

        securityHandler = new SecurityHandler(serverAddress);

    }

    /**
     * Features: CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void platformOwnerLoginOverRESTSuccessAndIssuesRelevantTokenTypeWithPOAttributes() throws IOException,
            TimeoutException, MalformedJWTException, JSONException, CertificateException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        Token token = securityHandler.requestCoreToken(platformOwnerUsername, platformOwnerPassword);
        assertNotNull(token.getToken());

        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());

        //verify that JWT is of type Core as was released by a CoreAAM
        assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

        // verify that the token contains the platform owner public key
        byte[] applicationPublicKeyInRepository = userRepository.findOne
                (platformOwnerUsername).getCertificate().getX509().getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.decodeBase64(claimsFromToken.getSpk());
        assertArrayEquals(applicationPublicKeyInRepository, publicKeyFromToken);

        // verify that this JWT contains attributes relevant for platform owner
        Map<String, String> attributes = claimsFromToken.getAtt();
        // PO role
        assertEquals(UserRole.PLATFORM_OWNER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        // owned platform identifier
        assertEquals(preferredPlatformId, attributes.get(CoreAttributes.OWNED_PLATFORM.toString()));
    }

    /**
     * Features: CAAM - Providing platform details for Administration upon giving a correct Core Token
     * Interfaces: CAAM ;
     * CommunicationType AMQP
     */
    @Test
    public void platformOwnerLoginOverRESTAndReceivesInAdministrationDetailsOfHisOwnedPlatform() throws IOException,
            TimeoutException, MalformedJWTException, JSONException, CertificateException, TokenValidationException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // login the platform owner
        Token token = securityHandler.requestCoreToken(platformOwnerUsername, platformOwnerPassword);
        //verify that JWT was issued for user
        assertNotNull(token.getToken());

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (token.getToken()).getBytes());
        OwnedPlatformDetails ownedPlatformDetails = mapper.readValue(ownedPlatformRawResponse, OwnedPlatformDetails
                .class);

        Platform ownedPlatformInDB = platformRepository.findOne(preferredPlatformId);

        // verify the contents of the response
        assertEquals(ownedPlatformInDB.getPlatformInstanceFriendlyName(), ownedPlatformDetails
                .getPlatformInstanceFriendlyName());
        assertEquals(ownedPlatformInDB.getPlatformInstanceId(), ownedPlatformDetails.getPlatformInstanceId());
        assertEquals(ownedPlatformInDB.getPlatformInterworkingInterfaceAddress(), ownedPlatformDetails
                .getPlatformInterworkingInterfaceAddress());
    }

    /**
     * Features: CAAM - Providing platform details for Administration upon giving a correct Core Token
     * Interfaces: CAAM ;
     * CommunicationType AMQP
     */
    @Test
    public void nonPlatformOwnerLoginOverRESTAndIsDeclinedOwnedPlatformDetailsRequest() throws IOException,
            TimeoutException, MalformedJWTException, JSONException, CertificateException, TokenValidationException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // issue app registration over AMQP
        appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.APPLICATION))).getBytes());

        // login an ordinary user to get token
        Token token = securityHandler.requestCoreToken(coreAppUsername, coreAppPassword);
        //verify that JWT was issued for user
        assertNotNull(token.getToken());

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (token.getToken()).getBytes());

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(ownedPlatformRawResponse, ErrorResponseContainer
                .class);
        assertEquals(HttpStatus.UNAUTHORIZED.ordinal(), errorResponse.getErrorCode());
    }


    /**
     * Features: Core AAM  providing list of available security entry points
     * CommunicationType REST
     */
    @Test
    public void getAvailableAAMsOverRESTWithNoRegisteredPlatforms() throws NoSuchAlgorithmException,
            CertificateException, NoSuchProviderException, KeyStoreException, IOException, SecurityHandlerException {

        List<AAM> aams = securityHandler.getAvailableAAMs();

        // there should be only core AAM in the list
        assertEquals(1, aams.size());

        // verifying the contents
        AAM aam = aams.get(0);
        // this expected PlatformAAM is due to the value stored in the issued certificate in the test keystore
        assertEquals(AAMConstants.AAM_CORE_AAM_INSTANCE_ID, aam.getAamInstanceId());
        assertEquals(coreInterfaceAddress, aam.getAamAddress());
        // maybe we could externalize it to spring config
        assertEquals(AAMConstants.AAM_CORE_AAM_FRIENDLY_NAME, aam.getAamInstanceFriendlyName());
        assertEquals(registrationManager.getAAMCert(), aam.getCertificate().getCertificateString());
    }

    /**
     * Features: Core AAM  providing list of available security entrypoints
     * CommunicationType REST
     */
    @Test
    public void getAvailableAAMsOverRESTWithRegisteredPlatform()
            throws AAMException, IOException, TimeoutException, SecurityHandlerException {
        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // get the list
        List<AAM> aams = securityHandler.getAvailableAAMs();

        // there should be only core AAM in the list
        assertEquals(2, aams.size());

        // verifying the contents
        // first should be served the core AAM
        AAM coreAAM = aams.get(0);
        // this expected PlatformAAM is due to the value stored in the issued certificate in the test keystore
        assertEquals(AAMConstants.AAM_CORE_AAM_INSTANCE_ID, coreAAM.getAamInstanceId());
        assertEquals(coreInterfaceAddress, coreAAM.getAamAddress());
        assertEquals(AAMConstants.AAM_CORE_AAM_FRIENDLY_NAME, coreAAM.getAamInstanceFriendlyName());

        // then comes the registered platform
        AAM platformAAM = aams.get(1);
        assertEquals(preferredPlatformId, platformAAM.getAamInstanceId());
        assertEquals(platformInterworkingInterfaceAddress + platformAAMSuffixAtInterWorkingInterface, platformAAM
                .getAamAddress());
        assertEquals(platformInstanceFriendlyName, platformAAM.getAamInstanceFriendlyName());
        // TODO we don't know the cert... until R3 when we will know it
        assertEquals("", platformAAM.getCertificate().getCertificateString());
    }
}