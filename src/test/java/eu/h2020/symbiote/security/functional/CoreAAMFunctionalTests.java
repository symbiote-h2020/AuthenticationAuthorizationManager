package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.commons.Platform;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.AAMException;
import eu.h2020.symbiote.security.exceptions.aam.*;
import eu.h2020.symbiote.security.payloads.*;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.codehaus.jettison.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.test.context.TestPropertySource;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for Core AAM deployment scenarios.
 */
@TestPropertySource("/core.properties")
public class CoreAAMFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(CoreAAMFunctionalTests.class);
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

    @Bean
    DummyPlatformAAM getDummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

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

    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationOverAMQPFailureUnauthorized() throws IOException, TimeoutException {

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
    public void applicationRegistrationOverAMQPFailureWrongUserRole() throws IOException, TimeoutException {

        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue the same app registration over AMQP expecting with wrong PlatformOwner UserRole
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.PLATFORM_OWNER)))
                .getBytes());

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
    public void applicationRegistrationOverAMQPFailureUsernameExists() throws IOException, TimeoutException {
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
    public void applicationRegistrationOverAMQPFailureMissingAppUsername() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue app registration over AMQP with missing username
        appUserDetails.getCredentials().setUsername("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserRegistrationRequest)
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
    public void applicationRegistrationOverAMQPFailureMissingAppPassword() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue app registration over AMQP with missing password
        appUserDetails.getCredentials().setPassword("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserRegistrationRequest)
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
    public void applicationRegistrationOverAMQPFailureMissingAppFederatedId() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));


        // issue app registration over AMQP with missing federatedId
        appUserDetails.setFederatedID("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserRegistrationRequest)
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
    public void applicationRegistrationOverAMQPFailureMissingRecoveryMail() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(userRepository.findOne(coreAppUsername));

        // issue app registration over AMQP with missing recovery mail
        appUserDetails.setRecoveryMail("");
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(appUserRegistrationRequest)
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
    public void applicationRegistrationOverAMQPSuccess() throws IOException, TimeoutException, CertificateException,
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
        assertNotNull(appRegistrationResponse.getUserCertificate());
        assertNotNull(appRegistrationResponse.getUserPrivateKey());

        // TODO verify that released certificate has no CA property
    }

    /**
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */
    @Test
    public void federatedLoginToCoreUsingPlatformTokenOverRESTSuccess() throws TokenValidationException, IOException,
            TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException,
            NoSuchAlgorithmException {
        // issuing dummy platform token
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "testaam-1";
        // registering the platform to the Core AAM so it will be available for token revocation
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(platformId);
        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress(serverAddress + "/test");
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        //inject platform PEM Certificate to the database
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/TestAAM-1.p12"), "1234567".toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(platformId);
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        String dummyPlatformAAMPEMCertString = signedCertificatePEMDataStringWriter.toString();
        Platform dummyPlatform = platformRepository.findOne(platformId);
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // preparing request
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(AAMConstants.TOKEN_HEADER_NAME, dummyHomeToken.getToken());

        HttpEntity<String> entity = new HttpEntity<>(null, httpHeaders);

        // checking issuing of federated token using the dummy platform token
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants
                .AAM_REQUEST_FOREIGN_TOKEN, entity, String.class);
        HttpHeaders rspHeaders = response.getHeaders();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(rspHeaders.getFirst(AAMConstants.TOKEN_HEADER_NAME));
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPWithPreferredPlatformIdSuccess() throws IOException, TimeoutException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        PlatformRegistrationResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformRegistrationResponse.class);

        // verify that the server returns certificate & privateKey
        assertNotNull(platformRegistrationOverAMQPResponse.getPlatformOwnerCertificate());
        assertNotNull(platformRegistrationOverAMQPResponse.getPlatformOwnerPrivateKey());

        // TODO verify that released PO certificate has no CA property

        // TODO R3 verify that released platform certificate has CA property

        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationOverAMQPResponse.getPlatformId());

        // verify that PO is in repository (as PO!)
        User registeredPlatformOwner = userRepository.findOne(platformOwnerUsername);
        assertNotNull(registeredPlatformOwner);
        assertEquals(UserRole.PLATFORM_OWNER, registeredPlatformOwner.getRole());

        // verify that platform with preferred id is in repository and is tied with the given PO
        Platform registeredPlatform = platformRepository.findOne(preferredPlatformId);
        assertNotNull(registeredPlatform);
        assertEquals(platformOwnerUsername, registeredPlatform.getPlatformOwner().getUsername());

        // verify that platform oriented fields are properly stored
        assertEquals(platformInterworkingInterfaceAddress, registeredPlatform.getPlatformInterworkingInterfaceAddress
                ());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPWithGeneratedPlatformIdSuccess() throws IOException, TimeoutException {
        // verify that our platformOwner is not in repository
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without preferred platform identifier
        platformRegistrationOverAMQPRequest.setPlatformInstanceId("");
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        PlatformRegistrationResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformRegistrationResponse.class);

        // verify that the server returns certificate & privateKey
        assertNotNull(platformRegistrationOverAMQPResponse.getPlatformOwnerCertificate());
        assertNotNull(platformRegistrationOverAMQPResponse.getPlatformOwnerPrivateKey());

        // TODO verify that released PO certificate has no CA property

        // TODO R3 verify that released platform certificate has CA property

        // verified that we received a generated platformId
        String generatedPlatformId = platformRegistrationOverAMQPResponse.getPlatformId();
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
        assertEquals(platformInterworkingInterfaceAddress, registeredPlatform.getPlatformInterworkingInterfaceAddress
                ());
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

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(platformOwnerUsername, platformOwnerPassword), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        //verify that JWT was issued for user
        assertNotNull(headers.getFirst(AAMConstants.TOKEN_HEADER_NAME));

        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(AAMConstants.TOKEN_HEADER_NAME));

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
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailureUnauthorized() throws IOException, TimeoutException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP expecting with wrong AAMOwnerUsername
        platformRegistrationOverAMQPRequest.getAAMOwnerCredentials().setUsername(AAMOwnerUsername + "somethingWrong");
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(UnauthorizedRegistrationException.errorMessage, errorResponse.getErrorMessage());

        // issue platform registration over AMQP expecting with wrong AAMOwnerUsername
        platformRegistrationOverAMQPRequest.getAAMOwnerCredentials().setUsername(AAMOwnerUsername);
        platformRegistrationOverAMQPRequest.getAAMOwnerCredentials().setPassword(AAMOwnerPassword + "somethingWrong");
        response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

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
    public void platformRegistrationOverAMQPFailureMissingAAMURL() throws IOException, TimeoutException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without required Platform's AAM URL
        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress("");
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailureMissingFriendlyName() throws IOException, TimeoutException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without required Platform's instance friendly name
        platformRegistrationOverAMQPRequest.setPlatformInstanceFriendlyName("");
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailurePOUsernameExists() throws IOException, TimeoutException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // verify that platform with preferred id is in repository and is tied with the given PO
        PlatformRegistrationResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformRegistrationResponse.class);
        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationOverAMQPResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        // issue registration request with different preferred platform identifier but for the same PO
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(preferredPlatformId + "different");
        response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(ExistingUserException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailurePreferredPlatformIdExists() throws IOException, TimeoutException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // verify that platform with preferred id is in repository and is tied with the given PO
        PlatformRegistrationResponse platformRegistrationOverAMQPResponse = mapper.readValue(response,
                PlatformRegistrationResponse.class);
        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationOverAMQPResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        // issue registration request with the same preferred platform identifier but different PO
        platformRegistrationOverAMQPRequest.getPlatformOwnerDetails().getCredentials().setUsername
                (platformOwnerUsername + "differentOne");
        response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(ExistingPlatformException.errorMessage, errorResponse.getErrorMessage());
    }


    /**
     * Features: CAAM - Providing platform details for Administration upon giving a correct Core Token
     * Interfaces: CAAM ;
     * CommunicationType AMQP
     */
    @Test
    public void platformOwnerLoginOverRESTAndReceivesInAdministrationDetailsOfHisOwnedPlatform() throws IOException,
            TimeoutException, MalformedJWTException, JSONException, CertificateException, TokenValidationException,
            InterruptedException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // login the platform owner
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(platformOwnerUsername, platformOwnerPassword), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        //verify that JWT was issued for user
        assertNotNull(headers.getFirst(AAMConstants.TOKEN_HEADER_NAME));

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (headers.getFirst(AAMConstants.TOKEN_HEADER_NAME)).getBytes());
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
    public void platformOwnerLoginOverRESTAndUsesExpiredTokenToReceivesInAdministrationDetailsOfHisOwnedPlatform() throws IOException,
            TimeoutException, MalformedJWTException, JSONException, CertificateException, TokenValidationException,
            InterruptedException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // login the platform owner
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(platformOwnerUsername, platformOwnerPassword), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        //verify that JWT was issued for user
        assertNotNull(headers.getFirst(AAMConstants.TOKEN_HEADER_NAME));

        // waiting for the token to expire
        Thread.sleep(tokenValidityPeriod + 1000);

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (headers.getFirst(AAMConstants.TOKEN_HEADER_NAME)).getBytes());

        try {
            mapper.readValue(ownedPlatformRawResponse, OwnedPlatformDetails.class);
            assert false;
        } catch (Exception e) {
            ErrorResponseContainer error = mapper.readValue(ownedPlatformRawResponse, ErrorResponseContainer.class);
            assertEquals(HttpStatus.UNAUTHORIZED.value(), error.getErrorCode());
        }
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
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(coreAppUsername, coreAppPassword), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        //verify that JWT was issued for user
        assertNotNull(headers.getFirst(AAMConstants.TOKEN_HEADER_NAME));

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (headers.getFirst(AAMConstants.TOKEN_HEADER_NAME)).getBytes());

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(ownedPlatformRawResponse, ErrorResponseContainer
                .class);
        assertEquals(HttpStatus.UNAUTHORIZED.value(), errorResponse.getErrorCode());
    }


    /**
     * Features: Core AAM  providing list of available security entry points
     * CommunicationType REST
     */
    @Test
    public void getAvailableAAMsOverRESTWithNoRegisteredPlatforms() throws NoSuchAlgorithmException,
            CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        ResponseEntity<List<AAM>> response = restTemplate.exchange(serverAddress + AAMConstants
                .AAM_GET_AVAILABLE_AAMS, HttpMethod.GET, null, new ParameterizedTypeReference<List<AAM>>() {
        });
        assertEquals(HttpStatus.OK, response.getStatusCode());

        // verify the body
        List<AAM> aams = response.getBody();
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
    public void getAvailableAAMsOverRESTWithRegisteredPlatform() throws AAMException, IOException, TimeoutException {
        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // get the list
        ResponseEntity<List<AAM>> response = restTemplate.exchange(serverAddress + AAMConstants
                .AAM_GET_AVAILABLE_AAMS, HttpMethod.GET, null, new ParameterizedTypeReference<List<AAM>>() {
        });
        assertEquals(HttpStatus.OK, response.getStatusCode());

        // verify the body
        List<AAM> aams = response.getBody();
        // there should be Core AAM and the registered platform
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