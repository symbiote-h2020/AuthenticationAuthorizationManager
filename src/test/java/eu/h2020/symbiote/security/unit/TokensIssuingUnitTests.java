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
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.GetCertificateService;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
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
import java.util.concurrent.TimeoutException;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class TokensIssuingUnitTests extends AbstractAAMTestSuite {


    private static Log log = LogFactory.getLog(CertificatesIssuingUnitTests.class);
    protected final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

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
    @Autowired
    private TokenIssuer tokenIssuer;
    @Autowired
    private GetTokenService getTokenService;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;

    @Autowired
    ComponentCertificatesRepository componentCertificatesRepository;
    @Autowired
    private GetCertificateService getCertificateService;

    @Bean
    DummyPlatformAAM dummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

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
    public void getHomeTokenByUserSuccess() throws
            IOException,
            TimeoutException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            JWTCreationException,
            MalformedJWTException,
            CertificateException,
            OperatorCreationException,
            InvalidKeyException,
            KeyStoreException,
            UnrecoverableKeyException {
        addTestUserWithClientCertificateToRepository();
        User user = userRepository.findOne(username);
        assertNotNull(user);
        Token token = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.toString());
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        Map<String, String> attributes = claimsFromToken.getAtt();
        assertEquals(UserRole.USER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        // verify that the token contains the user public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (username).getClientCertificates().get(clientId).getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.getDecoder().decode(claimsFromToken.getSpk());

        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);
    }

    @Test
    public void getHomeTokenByPlatformOwnerSuccess() throws
            IOException,
            TimeoutException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            JWTCreationException,
            MalformedJWTException,
            CertificateException,
            KeyStoreException,
            OperatorCreationException,
            UnrecoverableKeyException,
            InvalidKeyException {
        //platformOwner registration and certificate
        User user = new User();
        user.setRole(UserRole.PLATFORM_OWNER);
        user.setUsername(platformOwnerUsername);
        user.setPasswordEncrypted(passwordEncoder.encode(platformOwnerPassword));
        user.setRecoveryMail("nullMail");

        KeyPair platformKeyPair = CryptoHelper.createKeyPair();
        String cn = "CN=" + platformOwnerUsername + "@" + federatedOAuthId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), platformKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(platformKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, federatedOAuthId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSRinPEMFormat());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        eu.h2020.symbiote.security.commons.Certificate cert = new eu.h2020.symbiote.security.commons.Certificate(pem);
        user.getClientCertificates().put(federatedOAuthId, cert);
        userRepository.save(user);

        Platform platform = new Platform("platformInstanceId", null, null, user, new Certificate(), new HashMap<>());
        platformRepository.save(platform);

        Token token = tokenIssuer.getHomeToken(user, federatedOAuthId, user.getClientCertificates().get(federatedOAuthId).getX509().getPublicKey());
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.toString());
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        Map<String, String> attributes = claimsFromToken.getAtt();
        assertEquals(UserRole.PLATFORM_OWNER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        // verify that the token contains the user public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (platformOwnerUsername).getClientCertificates().get(federatedOAuthId).getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.getDecoder().decode(claimsFromToken.getSpk());
        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);
    }

    @Test
    public void getHomeTokenByPlatformOwnerForComponentSuccess() throws
            IOException,
            TimeoutException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            JWTCreationException,
            MalformedJWTException,
            CertificateException,
            KeyStoreException,
            OperatorCreationException,
            UnrecoverableKeyException,
            InvalidKeyException,
            InvalidArgumentsException,
            UserManagementException,
            WrongCredentialsException,
            PlatformManagementException,
            NotExistingUserException, ValidationException {
        //platformOwner registration and certificate
        User user = new User();
        user.setRole(UserRole.PLATFORM_OWNER);
        user.setUsername(platformOwnerUsername);
        user.setPasswordEncrypted(passwordEncoder.encode(platformOwnerPassword));
        user.setRecoveryMail("nullMail");

        KeyPair platformKeyPair = CryptoHelper.createKeyPair();
        String cn = "CN=" + platformOwnerUsername + "@" + federatedOAuthId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), platformKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(platformKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, federatedOAuthId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSRinPEMFormat());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        eu.h2020.symbiote.security.commons.Certificate cert = new eu.h2020.symbiote.security.commons.Certificate(pem);
        user.getClientCertificates().put(federatedOAuthId, cert);
        userRepository.save(user);

        Platform platform = new Platform(federatedOAuthId, null, null, user, new Certificate(), new HashMap<>());
        platformRepository.save(platform);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, federatedOAuthId, pair);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = getCertificateService.getCertificate(certRequest);
        platform.getComponentCertificates().put(componentId, new Certificate(certificate));
        platformRepository.save(platform);
        user.getOwnedPlatforms().put(federatedOAuthId, platform);
        userRepository.save(user);

        Token token = tokenIssuer.getHomeToken(user, componentId + illegalSign + federatedOAuthId, user.getOwnedPlatforms().get(federatedOAuthId).getComponentCertificates().get(componentId).getX509().getPublicKey());
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.toString());
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        Map<String, String> attributes = claimsFromToken.getAtt();
        assertEquals(UserRole.PLATFORM_OWNER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        // verify that the token contains the user public key
        byte[] userPublicKeyInRepository = user.getOwnedPlatforms().get(federatedOAuthId).getComponentCertificates().get(componentId).getX509().getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.getDecoder().decode(claimsFromToken.getSpk());
        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);
    }

    @Test
    public void getHomeTokenSuccess() throws
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
    public void getHomeTokenWrongSign() throws
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
            ValidationException {
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        getTokenService.getHomeToken(loginRequest);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenWrongCredentials() throws
            IOException,
            ClassNotFoundException,
            CertificateException,
            InvalidArgumentsException,
            WrongCredentialsException,
            JWTCreationException,
            MalformedJWTException,
            ValidationException {
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        getTokenService.getHomeToken(loginRequest);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void getHomeTokenMissingCredentials() throws
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
            token = new Token(dummyPlatformAAM().getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
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

        // adding a dummy foreign rule
        tokenIssuer.foreignMappingRules.put("DummyRule", "dummyRule");
        Token foreignToken = null;
        try {
            foreignToken = getTokenService.getForeignToken(token, "", "");
        } catch (Exception e) {
            log.error(e.getMessage(), e.getCause());
            fail("Exception thrown");
        }
        assertNotNull(foreignToken);
        assertEquals(Token.Type.FOREIGN, foreignToken.getType());
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
            token = new Token(dummyPlatformAAM().getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        } catch (Exception e) {
            fail("Exception thrown");
        }
        tokenIssuer.foreignMappingRules.clear();
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
            token = new Token(dummyPlatformAAM().getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
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
            token = new Token(dummyPlatformAAM().getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
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

    @Test
    public void getHomeTokenForPlatformOwnerForComponentSuccessAndIssuesRelevantTokenTypeWithPOAttributes() throws
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
        // issue platform registration over AMQP
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        //platform owner adding
        platformRepository.save(platform);
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateString = getCertificateService.getCertificate(certRequest);
        platform.getComponentCertificates().put(componentId, new Certificate(certificateString));
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, componentId + illegalSign + platformId, null, pair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        Token homeToken = getTokenService.getHomeToken(loginRequest);
        //verify that JWT was issued for user
        assertNotNull(homeToken);

        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(homeToken.toString());

        //verify that JWT is of type Core as was released by a CoreAAM
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        // verify that the token contains the platform owner public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (platformOwnerUsername).getOwnedPlatforms().get(platformId).getComponentCertificates().get(componentId).getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.getDecoder().decode(claimsFromToken.getSpk());
        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);

        // verify that this JWT contains attributes relevant for platform owner
        Map<String, String> attributes = claimsFromToken.getAtt();
        // PO role
        assertEquals(UserRole.PLATFORM_OWNER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
    }

    @Test
    public void getHomeTokenForAdminForComponentSuccess() throws
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
        // issue platform registration over AMQP

        //platform owner adding
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);
        HomeCredentials homeCredentials = new HomeCredentials(null, AAMOwnerUsername, componentId + illegalSign + SecurityConstants.AAM_CORE_AAM_INSTANCE_ID, null, (PrivateKey) getPrivateKeyFromTestKeystore(
                "core.p12",
                "registry-core-1"));
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        Token homeToken = getTokenService.getHomeToken(loginRequest);
        //verify that JWT was issued for user
        assertNotNull(homeToken);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForAdminForComponentFailWrongSign() throws
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
        // issue platform registration over AMQP

        //platform owner adding
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);
        HomeCredentials homeCredentials = new HomeCredentials(null, AAMOwnerUsername, componentId + illegalSign + SecurityConstants.AAM_CORE_AAM_INSTANCE_ID, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        Token homeToken = getTokenService.getHomeToken(loginRequest);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenComponentFailWrongCredentials() throws
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

        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, componentId + illegalSign + SecurityConstants.AAM_CORE_AAM_INSTANCE_ID, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        Token homeToken = getTokenService.getHomeToken(loginRequest);
    }
    @Test
    @Ignore("Not R2 crucial, at R2 we will issue attributes from properties")
    public void getHomeTokenWithAttributesProvisionedToBeIssuedForGivenUser() throws IOException, TimeoutException {
        /*
        TODO attributes provisioning test
        2. send the attributes list
        3. receive a success status
        4. log in as an user and check if the token does contain sent attributes
        */
    }

    @Test
    @Ignore("Not R2")
    public void getForeignTokenWithForeignAttributesIssuedUsingProvisionedAttributesMappingListForGivenHomeToken() throws IOException,
            TimeoutException {
        /*
        // TODO attributes mapping list provisioning R3? R4?
        2. send an attribute mapping list
        3. receive a success status
        4. request foreign tokens which should be based on given tokens
        */
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
