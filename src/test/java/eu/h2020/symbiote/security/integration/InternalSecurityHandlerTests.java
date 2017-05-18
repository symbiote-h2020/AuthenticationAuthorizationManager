package eu.h2020.symbiote.security.integration;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AuthenticationAuthorizationManagerTests;
import eu.h2020.symbiote.security.InternalSecurityHandler;
import eu.h2020.symbiote.security.SecurityHandler;
import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.commons.Platform;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.exceptions.aam.*;
import eu.h2020.symbiote.security.functional.CoreAuthenticationAuthorizationManagerTests;
import eu.h2020.symbiote.security.payloads.*;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.codehaus.jettison.json.JSONException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Created by Maks on 2017-05-16.
 */
public class InternalSecurityHandlerTests extends AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CoreAuthenticationAuthorizationManagerTests.class);
    private final String coreAppUsername = "testCoreAppUsername";
    private final String coreAppPassword = "testCoreAppPassword";
    private final String recoveryMail = "null@dev.null";
    private final String federatedOAuthId = "federatedOAuthId";
    private final String preferredPlatformId = "preferredPlatformId";
    //private final String platformInstanceFriendlyName = "friendlyPlatformName";
    //private final String platformInterworkingInterfaceAddress =
    //        "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
    private final String platformOwnerUsername = "testPlatformOwnerUsername";
    private final String platformOwnerPassword = "testPlatormOwnerPassword";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    //private UserRegistrationRequest appUserRegistrationRequest;
    private RpcClient appRegistrationClient;
    //private UserDetails appUserDetails;
    private RpcClient platformRegistrationOverAMQPClient;
    //private UserDetails platformOwnerUserDetails;
    private PlatformRegistrationRequest platformRegistrationOverAMQPRequest;
    @Autowired
    private PlatformRepository platformRepository;

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private InternalSecurityHandler internalSecurityHandler;
    private String coreTokenString;
    private String platformTokenString;
    private String symbioteCoreInterfaceAddress;
    private AAM coreAAM;
    private String rabbitMQHostIP;
  //  private DummyAAMAMQPListener dummyAAMAMQPListener = new DummyAAMAMQPListener();



    @Before
    public void setUp() throws Exception {
        //dummyAAMAMQPListener.init();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());


        symbioteCoreInterfaceAddress = "http://localhost:18033";
        rabbitMQHostIP = "localhost";
        internalSecurityHandler = new InternalSecurityHandler(symbioteCoreInterfaceAddress, rabbitMQHostIP, "guest", "guest");

        final String ALIAS = "test aam keystore";
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/TestAAM.keystore"), "1234567".toCharArray());
        Key key = ks.getKey(ALIAS, "1234567".toCharArray());
        /*
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("name", "test2");
        coreTokenString = JWTEngine.generateJWTToken("test1", attributes, ks.getCertificate(ALIAS).getPublicKey()
                        .getEncoded(), IssuingAuthorityType.CORE, DateUtil.addDays(new Date(), 1).getTime(),
                "securityHandlerTestCoreAAM", ks.getCertificate(ALIAS).getPublicKey(), (PrivateKey) key);
        platformTokenString = JWTEngine.generateJWTToken("test1", attributes, ks.getCertificate(ALIAS).getPublicKey()
                        .getEncoded(), IssuingAuthorityType.PLATFORM, DateUtil.addDays(new Date(), 1).getTime(),
                "securityHandlerTestPlatformAAM", ks.getCertificate(ALIAS).getPublicKey(), (PrivateKey) key);
        */
        // coreAAM
        X509Certificate x509Certificate = (X509Certificate) ks.getCertificate("test aam keystore");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(x509Certificate);
        pemWriter.close();
        // XXX the instance id "PlatformAAM" is hardcoded in the keystore
        coreAAM = new AAM(symbioteCoreInterfaceAddress, "Core AAM", "PlatformAAM", new Certificate
                (signedCertificatePEMDataStringWriter.toString()));
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailureUnauthorizedUsingSecurityHandler() throws IOException, TimeoutException {
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
    public void platformRegistrationOverAMQPFailureMissingAAMURLUsingSecurityHandler() throws IOException, TimeoutException, SecurityHandlerException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without required Platform's AAM URL

        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress("");
        byte[] response = platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        
        //internalSecurityHandler.requestFederatedCoreToken(platformOwnerUsername,platformOwnerPassword);

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(MissingArgumentsException.errorMessage, errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    public void platformRegistrationOverAMQPFailureMissingFriendlyNameUsingSecurityHandler() throws IOException, TimeoutException {
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
    public void platformRegistrationOverAMQPFailurePOUsernameExistsUsingSecurityHandler() throws IOException, TimeoutException {
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
    public void platformRegistrationOverAMQPFailurePreferredPlatformIdExistsUsingSecurityHandler() throws IOException, TimeoutException {
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
    public void platformOwnerLoginOverRESTAndReceivesInAdministrationDetailsOfHisOwnedPlatformUsingSecurityHandler() throws IOException,
            TimeoutException, MalformedJWTException, JSONException, CertificateException, TokenValidationException, SecurityHandlerException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());


        SecurityHandler securityHandler = new SecurityHandler(serverAddress+ AAMConstants.AAM_LOGIN);
        Token token = securityHandler.requestCoreToken(platformOwnerUsername,platformOwnerPassword);
        assertNotNull(token.getToken());


        /*
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
        */

        //InternalSecurityHandler internalSecurityHandler = new InternalSecurityHandler(serverAddress,rabbitMQHostIP,
        //        "guest","guest");

        Token token2 = internalSecurityHandler.requestFederatedCoreToken(platformOwnerUsername,platformOwnerPassword);
        byte[] ownedPlatformRawResponse = token2.getToken().getBytes();
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
    public void nonPlatformOwnerLoginOverRESTAndIsDeclinedOwnedPlatformDetailsRequestUsingSecurityHandler() throws IOException,
            TimeoutException, MalformedJWTException, JSONException, CertificateException, TokenValidationException, SecurityHandlerException {
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


        SecurityHandler securityHandler = new SecurityHandler(serverAddress + AAMConstants.AAM_LOGIN);
        Token token = securityHandler.requestCoreToken(coreAppUsername,coreAppPassword);

        assertNotNull(token.getToken());
        /*
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
        */
        // verify error response
        //InternalSecurityHandler internalSecurityHandler = new InternalSecurityHandler(serverAddress + AAMConstants.AAM_LOGIN,
        //        rabbitMQHostIP, "guest","guest");

        Token token2 = internalSecurityHandler.requestFederatedCoreToken(coreAppUsername,coreAppPassword);
        byte[] ownedPlatformRawResponse = token2.getToken().getBytes();

        ErrorResponseContainer errorResponse = mapper.readValue(ownedPlatformRawResponse, ErrorResponseContainer
                .class);
        assertEquals(HttpStatus.UNAUTHORIZED.ordinal(), errorResponse.getErrorCode());
    }



    /**
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1 and CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationLoginOverAMQPSuccessAndIssuesCoreTokenTypeUsingSecurityHandler() throws IOException, TimeoutException, SecurityHandlerException {

        //InternalSecurityHandler internalSecurityHandler = new InternalSecurityHandler(serverAddress + AAMConstants.AAM_LOGIN,
        //        rabbitMQHostIP, "guest","guest");
        /*
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(username, password))
                .getBytes());

        Token token = mapper.readValue(response, Token.class);
        */
        Token token = internalSecurityHandler.requestHomeToken(username,password);

        log.info("Test Client received this Token: " + token.toString());

        assertNotNull(token.getToken());
        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
            assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

            // verify that the token contains the application public key
            byte[] applicationPublicKeyInRepository = userRepository.findOne
                    (username).getCertificate().getX509().getPublicKey().getEncoded();
            byte[] publicKeyFromToken = Base64.decodeBase64(claimsFromToken.getSpk());
            assertArrayEquals(applicationPublicKeyInRepository, publicKeyFromToken);
        } catch (MalformedJWTException | CertificateException e) {
            log.error(e);
        }
    }


    /**
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationLoginOverAMQPWrongCredentialsFailureUsingSecurityHandler() throws IOException, TimeoutException, SecurityHandlerException {

        //InternalSecurityHandler securityHandler = new InternalSecurityHandler(serverAddress + AAMConstants.AAM_LOGIN,
        //        rabbitMQHostIP, "guest","guest");


        /*
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);

        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(wrongusername, password))
                .getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);
        */
        Token token = internalSecurityHandler.requestHomeToken(wrongusername,password);
        ErrorResponseContainer noToken = mapper.readValue(token.getToken().getBytes(), ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());



        /*byte[] response2 = client.primitiveCall(mapper.writeValueAsString(new Credentials(username, wrongpassword))
                .getBytes());
          ErrorResponseContainer noToken = mapper.readValue(response2, ErrorResponseContainer.class);*/

        Token token2 = internalSecurityHandler.requestHomeToken(username,wrongpassword);
        ErrorResponseContainer noToken2 = mapper.readValue(token2.getToken().getBytes(), ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken2.getErrorMessage());


        /*byte[] token3 = client.primitiveCall(mapper.writeValueAsString(new Credentials(wrongusername,
                wrongpassword)).getBytes());
        ErrorResponseContainer noToken3 = mapper.readValue(response3, ErrorResponseContainer.class);
        */

        Token token3 = internalSecurityHandler.requestHomeToken(wrongusername,wrongpassword);
        ErrorResponseContainer noToken3 = mapper.readValue(token3.getToken().getBytes(), ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken3.getErrorMessage());


        String expectedErrorMessage = new WrongCredentialsException().getErrorMessage();

        assertEquals(expectedErrorMessage, noToken.getErrorMessage());
        assertEquals(expectedErrorMessage, noToken2.getErrorMessage());
        assertEquals(expectedErrorMessage, noToken3.getErrorMessage());
    }

    /**
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationLoginOverAMQPMissingArgumentsFailureUsingSecurityHandler() throws IOException, TimeoutException {

        InternalSecurityHandler securityHandler = new InternalSecurityHandler(serverAddress + AAMConstants.AAM_LOGIN,
                rabbitMQHostIP, "guest","guest");

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(/* no username and/or
        password */)).getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        assertEquals(new MissingArgumentsException().getErrorMessage(), noToken.getErrorMessage());
    }





}
