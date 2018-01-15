package eu.h2020.symbiote.security.unit;

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.GreenMailUtil;
import com.icegreen.greenmail.util.ServerSetupTest;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.CoreAttributes;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.FederationRule;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.entities.Attribute;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import javax.mail.Message;
import javax.mail.MessagingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class TokensIssuingUnitTests extends AbstractAAMTestSuite {
    private static Log log = LogFactory.getLog(CertificatesIssuingUnitTests.class);

    private final String platformInstanceFriendlyName = "friendlyPlatformName";

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
    private GreenMail testSmtp;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        testSmtp = new GreenMail(ServerSetupTest.SMTP);
        testSmtp.start();

    }

    @After
    public void tearDown() {
        testSmtp.stop();
    }

    // test for revokeHomeToken function
    @Test
    public void getGuestTokenSuccess() throws
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
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException {
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
            KeyStoreException,
            BlockedUserException {
        addTestUserWithClientCertificateToRepository();
        KeyPair keyPair = CryptoHelper.createKeyPair();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, keyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        getTokenService.getHomeToken(loginRequest);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserWrongCredentials() throws
            CertificateException,
            InvalidArgumentsException,
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException,
            ValidationException, BlockedUserException, IOException {
        //user is not in DB
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        getTokenService.getHomeToken(loginRequest);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void getHomeTokenForUserMissingCredentials() throws
            CertificateException,
            InvalidArgumentsException,
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException,
            ValidationException, BlockedUserException, IOException {
        HomeCredentials homeCredentials = new HomeCredentials(null, null, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        getTokenService.getHomeToken(loginRequest);
    }

    @Test
    public void getHomeTokenForComponentSuccess() throws
            IOException,
            MalformedJWTException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            UnrecoverableKeyException,
            JWTCreationException, WrongCredentialsException, InvalidArgumentsException, ValidationException, BlockedUserException {

        //component adding
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);
        HomeCredentials homeCredentials = new HomeCredentials(null, SecurityConstants.CORE_AAM_INSTANCE_ID, componentId, null, getPrivateKeyTestFromKeystore(
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
            MalformedJWTException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            JWTCreationException, WrongCredentialsException, InvalidArgumentsException, ValidationException, BlockedUserException {

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
    public void getHomeTokenWithAttributesProvisionedToBeIssuedForLocalUser() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, JWTCreationException, MalformedJWTException {

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
    public void getHomeTokenForBlockedUser() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException,
            WrongCredentialsException,
            JWTCreationException,
            MessagingException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Boolean inserted = anomaliesHelper.insertBlockedActionEntry(new HandleAnomalyRequest(username + illegalSign + clientId, EventType.ACQUISITION_FAILED, System.currentTimeMillis(), 100000));
        assertTrue(inserted);
        try {
            getTokenService.getHomeToken(loginRequest);
            fail();
        } catch (BlockedUserException e) {
            log.info("Proper error caught");
        }
        Message[] messages = testSmtp.getReceivedMessages();
        assertEquals(1, messages.length);
        assertEquals("Your action was blocked", messages[0].getSubject());
        String body = GreenMailUtil.getBody(messages[0]).replaceAll("=\r?\n", "");
        assertTrue(body.contains(clientId));

        assertEquals(SecurityConstants.CORE_AAM_INSTANCE_ID, messages[0].getHeader("From")[0]);
        assertTrue(messages[0].getHeader("To")[0].contains("nullMail"));
    }

    @Test
    public void getHomeTokenForBlockedComponent() throws
            IOException,
            CertificateException,
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException,
            WrongCredentialsException,
            JWTCreationException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            UnrecoverableKeyException {

        //component adding
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);
        HomeCredentials homeCredentials = new HomeCredentials(null, SecurityConstants.CORE_AAM_INSTANCE_ID, componentId, null, getPrivateKeyTestFromKeystore(
                "core.p12",
                "registry-core-1"));
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        Boolean inserted = anomaliesHelper.insertBlockedActionEntry(new HandleAnomalyRequest(SecurityConstants.CORE_AAM_INSTANCE_ID + illegalSign + componentId, EventType.ACQUISITION_FAILED, System.currentTimeMillis(), 100000));
        assertTrue(inserted);
        try {
            getTokenService.getHomeToken(loginRequest);
            fail();
        } catch (BlockedUserException e) {
            log.info("Proper error caught");
        }
        Message[] messages = testSmtp.getReceivedMessages();
        assertEquals(0, messages.length);
    }

    @Test
    public void getHomeTokenWithAttributesProvisionedToBeIssuedForGivenUser() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, JWTCreationException, MalformedJWTException {

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
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            OperatorCreationException {

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

        User platformOwner = savePlatformOwner();
        //inject dummy platform with platform PEM Certificate to the database
        X509Certificate certificate = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        String dummyPlatformAAMPEMCertString = CryptoHelper.convertX509ToPEM(certificate);
        Platform dummyPlatform = new Platform(platformId,
                serverAddress + "/test",
                platformInstanceFriendlyName,
                platformOwner,
                new Certificate(dummyPlatformAAMPEMCertString),
                new HashMap<>());
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
            ValidationException,
            JWTCreationException {

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
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            JWTCreationException,
            OperatorCreationException {

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
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            JWTCreationException,
            OperatorCreationException {

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
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            JWTCreationException,
            OperatorCreationException {

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

        User platformOwner = savePlatformOwner();
        Platform dummyPlatform = new Platform(platformId,
                serverAddress + "/test",
                platformInstanceFriendlyName,
                platformOwner,
                new Certificate(),
                new HashMap<>());
        platformRepository.save(dummyPlatform);
        getTokenService.getForeignToken(token, "", "");
    }

}
