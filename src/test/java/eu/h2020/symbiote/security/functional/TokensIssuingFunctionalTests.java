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
import eu.h2020.symbiote.security.services.SignCertificateRequestService;
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
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class TokensIssuingFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(TokensIssuingFunctionalTests.class);
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
    private RpcClient attributesAddingOverAMQPClient;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    private LocalAttributesManagementRequest localUsersLocalAttributesManagementRequest;
    @Autowired
    private PlatformRepository platformRepository;
    @Autowired
    private SignCertificateRequestService signCertificateRequestService;

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
        String homeToken = aamClient.getHomeToken(loginRequest);
        assertNotNull(homeToken);
    }

    @Test(expected = MalformedJWTException.class)
    public void getHomeTokenForUserOverRESTIncorrectTokenFormat() throws JWTCreationException, MalformedJWTException, WrongCredentialsException {
        String homeToken = aamClient.getHomeToken("IncorrectlyFormattedToken");
        assertNotNull(homeToken);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserOverRESTWrongUsernameFailure() throws IOException, JWTCreationException, MalformedJWTException, WrongCredentialsException {

        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        aamClient.getHomeToken(loginRequest);
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
        aamClient.getHomeToken(loginRequest);
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

        String homeToken = aamClient.getHomeToken(loginRequest);
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

        String homeToken = aamClient.getHomeToken(loginRequest);
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
        String certificateString = signCertificateRequestService.getCertificate(certRequest);
        Platform platform = platformRepository.findOne(preferredPlatformId);
        platform.getComponentCertificates().put(componentId, new Certificate(certificateString));
        platformRepository.save(platform);
        user.getOwnedPlatforms().put(preferredPlatformId, platform);
        userRepository.save(user);

        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, componentId + illegalSign + preferredPlatformId, null, pair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = aamClient.getHomeToken(loginRequest);
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

        String homeToken = aamClient.getHomeToken(loginRequest);
        aamClient.getForeignToken(homeToken, Optional.empty(), Optional.empty());
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

        //checking token attributes
        JWTClaims claims = JWTEngine.getClaimsFromToken(dummyHomeToken.getToken());
        assertTrue(claims.getAtt().containsKey("name"));
        assertTrue(claims.getAtt().containsValue("test2"));
        // adding a federation rule
        Map<String, String> requiredAttr = new HashMap<>();
        requiredAttr.put("name", "test2");
        Map<String, String> releasedFederatedAttr = new HashMap<>();
        releasedFederatedAttr.put("federatedKey", "federaredAttribute");

        FederationRule federationRule = new FederationRule("federationId", requiredAttr, releasedFederatedAttr);
        federationRulesRepository.save(federationRule);

        // checking issuing of foreign token using the dummy platform token
        String token = aamClient.getForeignToken(dummyHomeToken.getToken(), Optional.empty(), Optional.empty());
        // check if returned status is ok and if there is token in header
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token);
        assertEquals(Token.Type.FOREIGN, Token.Type.valueOf(claimsFromToken.getTtyp()));
        assertTrue(claimsFromToken.getAtt().containsKey(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "federatedKey"));
        assertTrue(claimsFromToken.getAtt().containsValue("federaredAttribute"));
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
        // adding a federation rule
        Map<String, String> requiredAttr = new HashMap<>();
        requiredAttr.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "key", "attribute");
        Map<String, String> releasedFederatedAttr = new HashMap<>();
        releasedFederatedAttr.put("federatedKey", "federaredAttribute");

        FederationRule federationRule = new FederationRule("federationId", requiredAttr, releasedFederatedAttr);
        federationRulesRepository.save(federationRule);

        // checking issuing of foreign token using the dummy platform token
        aamClient.getForeignToken(dummyHomeToken.getToken(), Optional.empty(), Optional.empty());
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
        // adding a federation rule
        Map<String, String> requiredAttr = new HashMap<>();
        requiredAttr.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "key", "attribute");
        Map<String, String> releasedFederatedAttr = new HashMap<>();
        releasedFederatedAttr.put("federatedKey", "federaredAttribute");

        FederationRule federationRule = new FederationRule("federationId", requiredAttr, releasedFederatedAttr);
        federationRulesRepository.save(federationRule);

        // checking issuing of foreign token using the dummy platform token
        aamClient.getForeignToken(dummyHomeToken.getToken(), Optional.empty(), Optional.empty());
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
        federationRulesRepository.deleteAll();

        // checking issuing of foreign token using the dummy platform token
        aamClient.getForeignToken(dummyHomeToken.getToken(), Optional.empty(), Optional.empty());
    }

    @Test
    public void getGuestTokenOverRESTSuccess() throws MalformedJWTException, JWTCreationException {
        String acquired_token = aamClient.getGuestToken();
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
