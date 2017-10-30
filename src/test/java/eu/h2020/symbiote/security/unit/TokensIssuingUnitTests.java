package eu.h2020.symbiote.security.unit;

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
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.FederationRule;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.entities.Attribute;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.SignCertificateRequestService;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class TokensIssuingUnitTests extends AbstractAAMTestSuite {
    private static Log log = LogFactory.getLog(CertificatesIssuingUnitTests.class);

    private final String federatedOAuthId = "federatedOAuthId";
    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";

    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    String coreInterfaceAddress;
    @Autowired
    ComponentCertificatesRepository componentCertificatesRepository;
    @Autowired
    DummyPlatformAAM dummyPlatformAAM;
    @Autowired
    private TokenIssuer tokenIssuer;
    @Autowired
    private GetTokenService getTokenService;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    @Autowired
    private SignCertificateRequestService signCertificateRequestService;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // platform registration useful
        platformRegistrationOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformManagementRequestQueue, 5000);
        platformOwnerUserCredentials = new Credentials(platformOwnerUsername, platformOwnerPassword);
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId, OperationType.CREATE);
    }


    // test for revokeHomeToken function

    @Test
    public void getGuestTokenSuccess() throws
            IOException,
            TimeoutException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            JWTCreationException,
            MalformedJWTException {
        Token token = getTokenService.getGuestToken();
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.toString());
        assertEquals(Token.Type.GUEST, Token.Type.valueOf(claimsFromToken.getTtyp()));
        assertTrue(claimsFromToken.getAtt().isEmpty());
    }

    @Test
    public void getHomeTokenForUserSuccess() throws
            IOException,
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            InvalidKeyException,
            JWTCreationException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = null;
        try {
            token = getTokenService.getHomeToken(loginRequest);
        } catch (Exception e) {
            fail("Exception thrown");
        }
        assertNotNull(token);
        assertEquals(Token.Type.HOME, token.getType());
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserWrongSign() throws
            IOException,
            ClassNotFoundException,
            CertificateException,
            InvalidArgumentsException,
            WrongCredentialsException,
            JWTCreationException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            MalformedJWTException,
            ValidationException,
            OperatorCreationException,
            InvalidKeyException,
            KeyStoreException,
            UnrecoverableKeyException {
        addTestUserWithClientCertificateToRepository();
        KeyPair keyPair = CryptoHelper.createKeyPair();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, keyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        getTokenService.getHomeToken(loginRequest);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserWrongCredentials() throws
            IOException,
            ClassNotFoundException,
            CertificateException,
            InvalidArgumentsException,
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException,
            ValidationException {
        //user is not in DB
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        getTokenService.getHomeToken(loginRequest);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void getHomeTokenForUserMissingCredentials() throws
            IOException,
            ClassNotFoundException,
            CertificateException,
            InvalidArgumentsException,
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException,
            ValidationException {
        HomeCredentials homeCredentials = new HomeCredentials(null, null, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        getTokenService.getHomeToken(loginRequest);
    }

    @Test
    public void getHomeTokenForComponentSuccess() throws
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

        //component adding
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);
        HomeCredentials homeCredentials = new HomeCredentials(null, SecurityConstants.CORE_AAM_INSTANCE_ID, componentId, null, (PrivateKey) getPrivateKeyFromTestKeystore(
                "core.p12",
                "registry-core-1"));
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        Token homeToken = getTokenService.getHomeToken(loginRequest);
        //verify that JWT was issued for user
        assertNotNull(homeToken);
        assertEquals(componentId, homeToken.getClaims().getSubject());
        assertEquals(SecurityConstants.CORE_AAM_INSTANCE_ID, homeToken.getClaims().getIssuer());
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForComponentFailWrongSignature() throws
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

        //platform owner adding
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);
        HomeCredentials homeCredentials = new HomeCredentials(null, SecurityConstants.CORE_AAM_INSTANCE_ID, componentId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        getTokenService.getHomeToken(loginRequest);
    }

    @Test
    public void getHomeTokenWithAttributesProvisionedToBeIssuedForLocalUser() throws IOException, TimeoutException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException, JWTCreationException, MalformedJWTException {

        localUsersAttributesRepository.save(new Attribute("key", "attribute"));
        addTestUserWithClientCertificateToRepository();
        User user = userRepository.findOne(username);

        assertNotNull(user);
        Token token = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.toString());
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        Map<String, String> attributes = claimsFromToken.getAtt();
        assertEquals(UserRole.USER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        assertNotNull(attributes.get(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "key"));
        assertEquals("attribute", attributes.get(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "key"));
    }

    @Test
    public void getHomeTokenWithAttributesProvisionedToBeIssuedForGivenUser() throws IOException, TimeoutException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException, JWTCreationException, MalformedJWTException {

        addTestUserWithClientCertificateToRepository();
        User user = userRepository.findOne(username);
        Map<String, String> map = new HashMap<>();
        map.put("key", "attribute");
        user.setAttributes(map);
        userRepository.save(user);
        assertNotNull(user);
        Token token = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.toString());
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        Map<String, String> attributes = claimsFromToken.getAtt();
        assertEquals(UserRole.USER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        assertNotNull(attributes.get(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "key"));
        assertEquals("attribute", attributes.get(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "key"));
    }

    @Test
    public void getForeignTokenSuccess() throws
            IOException,
            ValidationException,
            TimeoutException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            UnrecoverableKeyException,
            OperatorCreationException,
            InvalidKeyException,
            JWTCreationException {

        addTestUserWithClientCertificateToRepository();
        assertNotNull(userRepository.findOne(username));

        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = null;
        try {
            token = new Token(dummyPlatformAAM.getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        } catch (Exception e) {
            fail("Exception thrown");
        }
        assertNotNull(token);
        String platformId = "platform-1";

        savePlatformOwner();

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
        FederationRule federationRule = new FederationRule("federationId", new HashSet<>());
        federationRule.addPlatform(dummyPlatform.getPlatformInstanceId());
        federationRulesRepository.save(federationRule);

        Token foreignToken = null;
        try {
            foreignToken = getTokenService.getForeignToken(token, "", "");
        } catch (Exception e) {
            log.error(e.getMessage(), e.getCause());
            fail("Exception thrown");
        }
        assertNotNull(foreignToken);
        assertEquals(Token.Type.FOREIGN, foreignToken.getType());
        JWTClaims claims = JWTEngine.getClaimsFromToken(foreignToken.toString());
        assertTrue(claims.getAtt().containsKey("federation_1"));
    }

    @Test(expected = JWTCreationException.class)
    public void getForeignTokenFailForUndefinedForeignMapping() throws
            IOException,
            ValidationException,
            TimeoutException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            JWTCreationException,
            UnrecoverableKeyException,
            OperatorCreationException,
            InvalidKeyException {

        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = null;
        try {
            token = new Token(dummyPlatformAAM.getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        } catch (Exception e) {
            fail("Exception thrown");
        }
        federationRulesRepository.deleteAll();
        tokenIssuer.getForeignToken(token);
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenFailsForHomeTokenUsedAsRequest() throws
            IOException,
            ValidationException,
            TimeoutException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            JWTCreationException,
            UnrecoverableKeyException,
            OperatorCreationException,
            InvalidKeyException {

        addTestUserWithClientCertificateToRepository();
        User user = userRepository.findOne(username);
        assertNotNull(user);
        Token token = null;
        try {
            token = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());
        } catch (Exception e) {
            fail("Exception thrown");
        }
        assertNotNull(token);
        getTokenService.getForeignToken(token, "", "");
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenFailsPlatformNotRegistered() throws
            IOException,
            ValidationException,
            TimeoutException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            JWTCreationException,
            UnrecoverableKeyException,
            OperatorCreationException,
            InvalidKeyException {

        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = null;
        try {
            token = new Token(dummyPlatformAAM.getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        } catch (Exception e) {
            fail("Exception thrown");
        }
        assertNotNull(token);
        getTokenService.getForeignToken(token, "", "");
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenFailsPlatformHasNotCertificate() throws
            IOException,
            ValidationException,
            TimeoutException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            JWTCreationException,
            UnrecoverableKeyException,
            OperatorCreationException,
            InvalidKeyException {

        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = null;
        try {
            token = new Token(dummyPlatformAAM.getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        } catch (Exception e) {
            fail("Exception thrown");
        }
        assertNotNull(token);
        String platformId = "platform-1";

        savePlatformOwner();

        // registering the platform to the Core AAM so it will be available for token revocation
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(platformId);
        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress(serverAddress + "/test");
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        getTokenService.getForeignToken(token, "", "");
    }

    private X509Certificate getCertificateFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
    }

    private Key getPrivateKeyFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return pkcs12Store.getKey(certificateAlias, KEY_STORE_PASSWORD.toCharArray());
    }

}
