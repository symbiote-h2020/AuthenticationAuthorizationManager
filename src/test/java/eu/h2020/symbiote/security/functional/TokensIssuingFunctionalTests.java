package eu.h2020.symbiote.security.functional;

import com.fasterxml.jackson.core.type.TypeReference;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.CoreAttributes;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.Attribute;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.GetCertificateService;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.codehaus.jettison.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeoutException;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class TokensIssuingFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(TokensIssuingFunctionalTests.class);
    private final String coreAppUsername = "testCoreAppUsername";
    private final String coreAppPassword = "testCoreAppPassword";
    private final String federatedOAuthId = "federatedOAuthId";
    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    @Value("${rabbit.queue.manage.attributes}")
    protected String attributeManagementRequestQueue;
    private KeyPair platformOwnerKeyPair;
    private RpcClient appRegistrationClient;
    private UserDetails appUserDetails;
    private RpcClient attributesAddingOverAMQPClient;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    private LocalAttributesManagementRequest localUsersLocalAttributesManagementRequest;
    @Autowired
    private PlatformRepository platformRepository;
    @Autowired
    private GetCertificateService getCertificateService;
    @Autowired
    private TokenIssuer tokenIssuer;

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

        // user registration useful
        appRegistrationClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                userManagementRequestQueue, 5000);
        appUserDetails = new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>());

        //user registration useful
        User user = new User();
        user.setUsername(platformOwnerUsername);
        user.setPasswordEncrypted(passwordEncoder.encode(platformOwnerPassword));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(user);

        // platform registration useful
        platformRegistrationOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformManagementRequestQueue, 5000);
        platformOwnerUserCredentials = new Credentials(user.getUsername(), user.getPasswordEncrypted());
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId, OperationType.CREATE);
        platformOwnerKeyPair = CryptoHelper.createKeyPair();

        attributesAddingOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                attributeManagementRequestQueue, 5000);
    }

    /**
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1 and CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void getHomeTokenForUserOverAMQPSuccessAndIssuesCoreTokenType() throws
            IOException,
            TimeoutException,
            MalformedJWTException,
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            InvalidKeyException,
            JWTCreationException {
        addTestUserWithClientCertificateToRepository();
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(loginRequest)
                .getBytes());
        Token token = mapper.readValue(response, Token.class);

        log.info("Test Client received this Token: " + token.toString());
        // check if token received
        assertNotNull(token);
        // check if issuing authority is core
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));
    }


    /**
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void getHomeTokenForUserOverAMQPWrongCredentialsFailure() throws
            IOException,
            TimeoutException,
            JWTCreationException {

        // test combinations of wrong credentials
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        HomeCredentials homeCredentials = new HomeCredentials(null, wrongusername, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(loginRequest)
                .getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        homeCredentials = new HomeCredentials(null, username, wrongClientId, null, userKeyPair.getPrivate());
        loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        byte[] response2 = client.primitiveCall(mapper.writeValueAsString(loginRequest)
                .getBytes());
        ErrorResponseContainer noToken2 = mapper.readValue(response2, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken2.getErrorMessage());
        homeCredentials = new HomeCredentials(null, wrongusername, wrongClientId, null, userKeyPair.getPrivate());
        loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        byte[] response3 = client.primitiveCall(mapper.writeValueAsString(loginRequest).getBytes());
        ErrorResponseContainer noToken3 = mapper.readValue(response3, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken3.getErrorMessage());

        String expectedErrorMessage = new WrongCredentialsException().getErrorMessage();

        assertEquals(expectedErrorMessage, noToken.getErrorMessage());
        assertEquals(expectedErrorMessage, noToken2.getErrorMessage());
        assertEquals(expectedErrorMessage, noToken3.getErrorMessage());
    }

    /**
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void getHomeTokenForUserOverAMQPMissingArgumentsFailure() throws
            IOException,
            TimeoutException,
            JWTCreationException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        HomeCredentials homeCredentials = new HomeCredentials(null, "", "", null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(loginRequest).getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        assertEquals(new InvalidArgumentsException().getErrorMessage(), noToken.getErrorMessage());
    }

    /**
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void getHomeTokenForUserOverAMQPWrongSignFailure() throws
            IOException,
            TimeoutException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            JWTCreationException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        KeyPair keyPair = CryptoHelper.createKeyPair();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, keyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(loginRequest).getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());
        assertEquals(new WrongCredentialsException().getErrorMessage(), noToken.getErrorMessage());
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserOverRESTWrongSignFailure() throws
            IOException,
            TimeoutException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            JWTCreationException, MalformedJWTException, WrongCredentialsException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, keyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        String homeToken = AAMClient.getHomeToken(loginRequest);
        assertNotNull(homeToken);
    }

    @Test(expected = MalformedJWTException.class)
    public void getHomeTokenForUserOverRESTIncorrectTokenFormat() throws JWTCreationException, MalformedJWTException, WrongCredentialsException {
        String homeToken = AAMClient.getHomeToken("IncorrectlyFormattedToken");
        assertNotNull(homeToken);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserOverRESTWrongUsernameFailure() throws IOException, JWTCreationException, MalformedJWTException, WrongCredentialsException {

        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        AAMClient.getHomeToken(loginRequest);
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserOverRESTWrongClientIdFailure() throws IOException, JWTCreationException, MalformedJWTException, WrongCredentialsException {
        HomeCredentials homeCredentials = new HomeCredentials(null, username, wrongClientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        AAMClient.getHomeToken(loginRequest);
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void getHomeTokenForUserOverRESTSuccessAndIssuesCoreTokenWithoutPOAttributes() throws
            IOException,
            MalformedJWTException,
            CertificateException,
            OperatorCreationException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            InvalidKeyException,
            JWTCreationException, WrongCredentialsException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = AAMClient.getHomeToken(loginRequest);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(homeToken);
        // As the AAM is now configured as core we confirm that relevant token type was issued.
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        // verify that this JWT contains attributes relevant for user role
        Map<String, String> attributes = claimsFromToken.getAtt();
        assertEquals(UserRole.USER.toString(), attributes.get(CoreAttributes.ROLE.toString()));

        // verify that the token contains the user public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (username).getClientCertificates().entrySet().iterator().next().getValue().getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.getDecoder().decode(claimsFromToken.getSpk());

        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);
    }

    /**
     * Features: CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void getHomeTokenForPlatformOwnerOverRESTSuccessAndIssuesRelevantTokenTypeWithPOAttributes() throws
            IOException,
            TimeoutException,
            MalformedJWTException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            OperatorCreationException,
            UnrecoverableKeyException,
            InvalidKeyException,
            JWTCreationException, WrongCredentialsException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        User user = userRepository.findOne(platformOwnerUsername);
        //platform owner adding
        String cn = "CN=" + platformOwnerUsername + "@" + platformId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), platformOwnerKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(platformOwnerKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSRinPEMFormat());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        Certificate cert = new Certificate(pem);
        user.getClientCertificates().put(platformId, cert);
        userRepository.save(user);

        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, platformId, null, platformOwnerKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = AAMClient.getHomeToken(loginRequest);
        //verify that JWT was issued for user
        assertNotNull(homeToken);

        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(homeToken);

        //verify that JWT is of type Core as was released by a CoreAAM
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        // verify that the token contains the platform owner public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (platformOwnerUsername).getClientCertificates().get(platformId).getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.getDecoder().decode(claimsFromToken.getSpk());
        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);

        // verify that this JWT contains attributes relevant for platform owner
        Map<String, String> attributes = claimsFromToken.getAtt();
        // PO role
        assertEquals(UserRole.PLATFORM_OWNER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        // owned platform identifier
    }

    @Test
    public void getHomeTokenForPlatformOwnerForComponentOverRESTSuccessAndIssuesRelevantTokenTypeWithPOAttributes() throws
            IOException,
            TimeoutException,
            MalformedJWTException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            OperatorCreationException,
            UnrecoverableKeyException,
            InvalidKeyException,
            JWTCreationException, WrongCredentialsException, InvalidAlgorithmParameterException, InvalidArgumentsException, NotExistingUserException, PlatformManagementException, UserManagementException, ValidationException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        User user = userRepository.findOne(platformOwnerUsername);
        //platform owner adding

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, preferredPlatformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateString = getCertificateService.getCertificate(certRequest);
        Platform platform = platformRepository.findOne(preferredPlatformId);
        platform.getComponentCertificates().put(componentId, new Certificate(certificateString));
        platformRepository.save(platform);
        user.getOwnedPlatforms().put(preferredPlatformId, platform);
        userRepository.save(user);

        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, componentId + illegalSign + preferredPlatformId, null, pair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = AAMClient.getHomeToken(loginRequest);
        //verify that JWT was issued for user
        assertNotNull(homeToken);

        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(homeToken);

        //verify that JWT is of type Core as was released by a CoreAAM
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        // verify that the token contains the platform owner public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (platformOwnerUsername).getOwnedPlatforms().get(preferredPlatformId).getComponentCertificates().get(componentId).getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.getDecoder().decode(claimsFromToken.getSpk());
        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);

        // verify that this JWT contains attributes relevant for platform owner
        Map<String, String> attributes = claimsFromToken.getAtt();
        // PO role
        assertEquals(UserRole.PLATFORM_OWNER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
    }

    /**
     * Features: CAAM - Providing platform details for Administration upon giving a correct Core Token
     * Interfaces: CAAM ;
     * CommunicationType AMQP
     */
    @Test
    public void getHomeTokenForPlatformOwnerOverRESTAndReceivesInAdministrationDetailsOfHisOwnedPlatform() throws
            IOException,
            TimeoutException,
            MalformedJWTException,
            JSONException,
            CertificateException,
            ValidationException,
            InterruptedException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            OperatorCreationException,
            UnrecoverableKeyException,
            InvalidKeyException,
            JWTCreationException, WrongCredentialsException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        User user = userRepository.findOne(platformOwnerUsername);
        //platform owner adding certificate
        String cn = "CN=" + platformOwnerUsername + "@" + preferredPlatformId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), platformOwnerKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(platformOwnerKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, preferredPlatformId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSRinPEMFormat());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        Certificate cert = new Certificate(pem);
        user.getClientCertificates().clear();
        user.getClientCertificates().put(preferredPlatformId, cert);
        userRepository.save(user);

        // getHomeToken the platform owner
        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, preferredPlatformId, null, platformOwnerKeyPair.getPrivate());

        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        String homeToken = AAMClient.getHomeToken(loginRequest);
        //verify that JWT was issued for user
        assertNotNull(homeToken);

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (homeToken).getBytes());

        Set<OwnedPlatformDetails> responseSet = mapper.readValue(ownedPlatformRawResponse, new TypeReference<Set<OwnedPlatformDetails>>() {
        });

        // there should be a platform
        assertFalse(responseSet.isEmpty());
        OwnedPlatformDetails platformDetailsFromResponse = responseSet.iterator().next();

        Platform ownedPlatformInDB = platformRepository.findOne(preferredPlatformId);

        // verify the contents of the response
        assertEquals(ownedPlatformInDB.getPlatformInstanceFriendlyName(), platformDetailsFromResponse
                .getPlatformInstanceFriendlyName());
        assertEquals(ownedPlatformInDB.getPlatformInstanceId(), platformDetailsFromResponse.getPlatformInstanceId());
        assertEquals(ownedPlatformInDB.getPlatformInterworkingInterfaceAddress(), platformDetailsFromResponse
                .getPlatformInterworkingInterfaceAddress());
    }


    /**
     * Features: CAAM - Providing platform details for Administration upon giving a correct Core Token
     * Interfaces: CAAM ;
     * CommunicationType AMQP
     */
    @Test
    public void getHomeTokenForPlatformOwnerOverRESTAndUsesExpiredTokenToReceivesInAdministrationDetailsOfHisOwnedPlatform()
            throws
            IOException,
            TimeoutException,
            MalformedJWTException,
            JSONException,
            CertificateException,
            ValidationException,
            InterruptedException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            OperatorCreationException,
            UnrecoverableKeyException,
            InvalidKeyException,
            JWTCreationException, WrongCredentialsException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        User user = userRepository.findOne(platformOwnerUsername);
        String cn = "CN=" + platformOwnerUsername + "@" + platformId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), platformOwnerKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(platformOwnerKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSRinPEMFormat());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        Certificate cert = new Certificate(pem);
        user.getClientCertificates().put(platformId, cert);
        userRepository.save(user);

        // getHomeToken the platform owner
        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, platformId, null, platformOwnerKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        String homeToken = AAMClient.getHomeToken(loginRequest);
        //verify that JWT was issued for user
        assertNotNull(homeToken);

        // waiting for the token to expire
        Thread.sleep(tokenValidityPeriod + 10);

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (homeToken).getBytes());

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
    public void getHomeTokenForPlatformOwnerOverRESTAndIsDeclinedOwnedPlatformDetailsRequestNoPlatform() throws
            IOException,
            TimeoutException,
            MalformedJWTException,
            JSONException,
            CertificateException,
            ValidationException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            OperatorCreationException,
            UnrecoverableKeyException,
            InvalidKeyException,
            JWTCreationException, WrongCredentialsException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // issue app registration over AMQP
        appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(coreAppUsername, coreAppPassword),
                new UserDetails(new Credentials(coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.USER, new HashMap<>()),
                OperationType.CREATE)).getBytes());

        //put certificate into database
        User user = userRepository.findOne(coreAppUsername);
        KeyPair keyPair = CryptoHelper.createKeyPair();
        String cn = "CN=" + coreAppUsername + "@" + platformId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(coreAppUsername, coreAppPassword, platformId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSRinPEMFormat());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        Certificate cert = new Certificate(pem);
        user.getClientCertificates().put(platformId, cert);
        userRepository.save(user);

        // getHomeToken an ordinary user to get token
        HomeCredentials homeCredentials = new HomeCredentials(null, coreAppUsername, platformId, null, keyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = AAMClient.getHomeToken(loginRequest);
        //verify that JWT was issued for user
        assertNotNull(homeToken);

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (homeToken).getBytes());

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(ownedPlatformRawResponse, ErrorResponseContainer.class);
        assertEquals(HttpStatus.UNAUTHORIZED.value(), errorResponse.getErrorCode());
    }

    /**
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */

    @Test(expected = ValidationException.class)
    public void getForeignTokenRequestOverRESTFailsForHomeTokenUsedAsRequest() throws
            IOException,
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            InvalidKeyException,
            JWTCreationException,
            ValidationException, MalformedJWTException, WrongCredentialsException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = AAMClient.getHomeToken(loginRequest);
        AAMClient.getForeignToken(homeToken, Optional.empty(), Optional.empty());
    }

    @Test
    public void getForeignTokenUsingPlatformTokenOverRESTSuccess() throws
            IOException,
            ValidationException,
            TimeoutException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            JWTCreationException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "platform-1";
        // registering the platform to the Core AAM so it will be available for token revocation
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(platformId);
        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress(serverAddress + "/test");
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        //inject platform PEM Certificate to the database
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/platform_1.p12"), "1234567".toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate("platform-1-1-c1");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        String dummyPlatformAAMPEMCertString = signedCertificatePEMDataStringWriter.toString();
        Platform dummyPlatform = platformRepository.findOne(platformId);
        dummyPlatform.setPlatformAAMCertificate(new eu.h2020.symbiote.security.commons.Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // adding a dummy foreign rule
        tokenIssuer.foreignMappingRules.put("DummyRule", "dummyRule");

        // checking issuing of foreign token using the dummy platform token
        String token = AAMClient.getForeignToken(dummyHomeToken.getToken(), Optional.empty(), Optional.empty());
        // check if returned status is ok and if there is token in header
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token);
        assertEquals(Token.Type.FOREIGN, Token.Type.valueOf(claimsFromToken.getTtyp()));
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenUsingPlatformTokenOverRESTFailPlatformNotRegistered() throws
            IOException,
            ValidationException,
            TimeoutException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            JWTCreationException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "platform-1";
        // registering the platform to the Core AAM so it will be available for token revocation
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(platformId);
        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress(serverAddress + "/test");
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // adding a dummy foreign rule
        tokenIssuer.foreignMappingRules.put("DummyRule", "dummyRule");

        // checking issuing of foreign token using the dummy platform token
        AAMClient.getForeignToken(dummyHomeToken.getToken(), Optional.empty(), Optional.empty());
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenUsingPlatformTokenOverRESTFailPlatformHasNotCertificate() throws
            IOException,
            ValidationException,
            TimeoutException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            JWTCreationException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // adding a dummy foreign rule
        tokenIssuer.foreignMappingRules.put("DummyRule", "dummyRule");

        // checking issuing of foreign token using the dummy platform token
        AAMClient.getForeignToken(dummyHomeToken.getToken(), Optional.empty(), Optional.empty());
    }

    /**
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */

    @Test(expected = JWTCreationException.class)
    public void getForeignTokenFromCoreUsingPlatformTokenOverRESTFailsForUndefinedForeignMapping() throws
            IOException,
            ValidationException,
            TimeoutException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            JWTCreationException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "platform-1";
        // registering the platform to the Core AAM so it will be available for token revocation
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(platformId);
        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress(serverAddress + "/test");
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        //inject platform PEM Certificate to the database
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/platform_1.p12"), "1234567".toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate("platform-1-1-c1");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        String dummyPlatformAAMPEMCertString = signedCertificatePEMDataStringWriter.toString();
        Platform dummyPlatform = platformRepository.findOne(platformId);
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // making sure the foreignMappingRules are empty
        tokenIssuer.foreignMappingRules.clear();

        // checking issuing of foreign token using the dummy platform token
        AAMClient.getForeignToken(dummyHomeToken.getToken(), Optional.empty(), Optional.empty());
    }

    @Test
    public void getGuestTokenOverRESTSuccess() throws MalformedJWTException, JWTCreationException {
        String acquired_token = AAMClient.getGuestToken();
        assertNotNull(acquired_token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(acquired_token);
        assertEquals(Token.Type.GUEST, Token.Type.valueOf(claimsFromToken.getTtyp()));
        assertTrue(claimsFromToken.getAtt().isEmpty());
    }

    @Test
    public void addAttributesOverAMQPSuccess() throws MalformedJWTException, JWTCreationException, IOException, TimeoutException {
        localUsersAttributesRepository.deleteAll();
        Map<String, String> attributesMap = new HashMap<>();
        attributesMap.put("key1", "attribute1");
        attributesMap.put("key2", "attribute2");
        localUsersLocalAttributesManagementRequest = new LocalAttributesManagementRequest(attributesMap, new Credentials(AAMOwnerUsername, AAMOwnerPassword), LocalAttributesManagementRequest.OperationType.WRITE);
        attributesAddingOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (localUsersLocalAttributesManagementRequest).getBytes());
        assertEquals(2, localUsersAttributesRepository.findAll().size());
    }

    @Test
    public void readAttributesOverAMQPSuccess() throws MalformedJWTException, JWTCreationException, IOException, TimeoutException {
        localUsersAttributesRepository.deleteAll();
        localUsersAttributesRepository.save(new Attribute("key1", "attribute1"));
        localUsersAttributesRepository.save(new Attribute("key2", "attribute2"));
        localUsersLocalAttributesManagementRequest = new LocalAttributesManagementRequest(new HashMap<>(), new Credentials(AAMOwnerUsername, AAMOwnerPassword), LocalAttributesManagementRequest.OperationType.READ);
        byte[] response = attributesAddingOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (localUsersLocalAttributesManagementRequest).getBytes());

        HashMap<String, String> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, String>>() {
        });
        assertEquals("attribute1", responseMap.get("key1"));
        assertEquals("attribute2", responseMap.get("key2"));
    }

    @Test
    public void readAttributesOverAMQPFailWrongCredentials() throws MalformedJWTException, JWTCreationException, IOException, TimeoutException {
        localUsersLocalAttributesManagementRequest = new LocalAttributesManagementRequest(new HashMap<>(), new Credentials(username, AAMOwnerPassword), LocalAttributesManagementRequest.OperationType.READ);
        byte[] response = attributesAddingOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (localUsersLocalAttributesManagementRequest).getBytes());

        ErrorResponseContainer fail = mapper.readValue(response, ErrorResponseContainer.class);
        assertNotNull(fail);
        log.info("Test Client received this error message instead of token: " + fail.getErrorMessage());

    }
}
