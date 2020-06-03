package eu.h2020.symbiote.security.unit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.entities.Attribute;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;

@TestPropertySource("/core.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class TokensIssuingUnitTests extends AbstractAAMTestSuite {
    private static Log log = LogFactory.getLog(CertificatesIssuingUnitTests.class);

    private final String platformInstanceFriendlyName = "friendlyPlatformName";

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
    public void getHomeTokenForUserSuccess() {
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
    public void getHomeTokenForUserFailWrongSign() throws
            CertificateException,
            InvalidArgumentsException,
            WrongCredentialsException,
            JWTCreationException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            MalformedJWTException,
            ValidationException {
        addTestUserWithClientCertificateToRepository();
        KeyPair keyPair = CryptoHelper.createKeyPair();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, keyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        getTokenService.getHomeToken(loginRequest);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserFailAccountNotActive() throws
            CertificateException,
            InvalidArgumentsException,
            WrongCredentialsException,
            JWTCreationException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            MalformedJWTException,
            ValidationException {
        addTestUserWithClientCertificateToRepository();
        // blocking the user
        User user = userRepository.findById(username).get();
        user.setStatus(AccountStatus.ACTIVITY_BLOCKED);
        userRepository.save(user);

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
            ValidationException {
        //user is not in DB
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        getTokenService.getHomeToken(loginRequest);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserWrongClientId() throws
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            CertificateException,
            ValidationException,
            InvalidArgumentsException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, wrongClientId, null, userKeyPair.getPrivate());
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
            ValidationException {
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
            JWTCreationException, WrongCredentialsException, InvalidArgumentsException, ValidationException {

        //component adding
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "keystores/core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);
        HomeCredentials homeCredentials = new HomeCredentials(null, SecurityConstants.CORE_AAM_INSTANCE_ID, componentId, null, getPrivateKeyTestFromKeystore(
                "keystores/core.p12",
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
            JWTCreationException, WrongCredentialsException, InvalidArgumentsException, ValidationException {

        //platform owner adding
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "keystores/core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);
        HomeCredentials homeCredentials = new HomeCredentials(null, SecurityConstants.CORE_AAM_INSTANCE_ID, componentId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        getTokenService.getHomeToken(loginRequest);
    }

    @Test
    public void getHomeTokenWithAttributesProvisionedToBeIssuedForLocalUser() throws CertificateException, JWTCreationException, MalformedJWTException {

        localUsersAttributesRepository.save(new Attribute("key", "attribute"));
        addTestUserWithClientCertificateToRepository();
        User user = userRepository.findById(username).get();

        assertNotNull(user);
        Token token = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.toString());
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        Map<String, String> attributes = claimsFromToken.getAtt();
        assertNotNull(attributes.get(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "key"));
        assertEquals("attribute", attributes.get(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "key"));
    }

    @Test
    public void getHomeTokenWithAttributesProvisionedToBeIssuedForGivenUser() throws CertificateException, JWTCreationException, MalformedJWTException {

        addTestUserWithClientCertificateToRepository();
        User user = userRepository.findById(username).get();
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
        assertNotNull(attributes.get(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "key"));
        assertEquals("attribute", attributes.get(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "key"));
    }

    @Test(expected = MalformedJWTException.class)
    public void getHomeTokenFailIncorrectTokenFormat() throws
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            InvalidArgumentsException,
            CertificateException,
            ValidationException {
        getTokenService.getHomeToken("IncorrectlyFormattedToken");
    }

    @Test
    public void getForeignTokenSuccess() throws
            IOException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException {

        addTestUserWithClientCertificateToRepository();
        assertNotNull(userRepository.findById(username));

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
        X509Certificate certificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        String dummyPlatformAAMPEMCertString = CryptoHelper.convertX509ToPEM(certificate);
        Platform dummyPlatform = new Platform(platformId,
                serverAddress + "/test",
                platformInstanceFriendlyName,
                platformOwner,
                new Certificate(dummyPlatformAAMPEMCertString),
                new HashMap<>());
        platformRepository.save(dummyPlatform);
        // adding a federation
        List<FederationMember> platformsId = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId(dummyPlatform.getPlatformInstanceId());
        platformsId.add(federationMember);

        Federation federation = new Federation();
        federation.setMembers(platformsId);
        federation.setId("federationId");
        federationsRepository.save(federation);

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
        federationsRepository.deleteAll();
        tokenIssuer.getForeignToken(token);
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenFailsForLocalHomeTokenUsedAsRequest() throws
            ValidationException,
            JWTCreationException {

        addTestUserWithClientCertificateToRepository();
        User user = userRepository.findById(username).get();
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
            ValidationException,
            JWTCreationException {

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
            ValidationException,
            JWTCreationException {

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
