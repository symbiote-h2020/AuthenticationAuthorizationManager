package eu.h2020.symbiote.security.unit;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.CoreAttributes;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
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
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class TokensIssuingUnitTests extends AbstractAAMTestSuite {


    private static Log log = LogFactory.getLog(ClientCertificatesIssuingUnitTests.class);
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
    @Autowired
    private RevocationHelper revocationHelper;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;

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
                platformRegistrationRequestQueue, 5000);
        platformOwnerUserCredentials = new Credentials(platformOwnerUsername, platformOwnerPassword);
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId);
    }


    // test for revokeHomeToken function
    @Test
    public void revokeUserToken() throws SecurityException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, UnrecoverableKeyException, OperatorCreationException {
        addTestUserWithClientCertificateToRepository();

        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId);

        // verify the user token is not yet revoked
        assertFalse(revokedTokensRepository.exists(homeToken.getClaims().getId()));
        // revocation
        revocationHelper.revokeHomeToken(new Credentials(username, password), homeToken);

        // verify the user token is revoked
        assertTrue(revokedTokensRepository.exists(homeToken.getClaims().getId()));
    }

    // test for revokeHomeToken function
    @Test
    public void revokeUserTokenByPlatform() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, WrongCredentialsException, NotExistingUserException, InvalidKeyException, OperatorCreationException, UnrecoverableKeyException, JWTCreationException {    // issuing dummy platform token
        User user = new User();
        user.setUsername(platformOwnerUsername);
        user.setPasswordEncrypted(passwordEncoder.encode(platformOwnerPassword));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.PLATFORM_OWNER);
        String cn = "CN=" + platformOwnerUsername + "@" + preferredPlatformId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), userKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(userKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, preferredPlatformId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSRinPEMFormat());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        eu.h2020.symbiote.security.commons.Certificate cert = new eu.h2020.symbiote.security.commons.Certificate(pem);

        user.getClientCertificates().put(federatedOAuthId, cert);

        userRepository.save(user);

        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" + SecurityConstants
                        .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "platform-1";
        // registering the platform to the Core AAM so it will be available for token revocation
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(platformId);
        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress(serverAddress + "/test");

        // issue platform registration over AMQP
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

        // ensure that token is not in revoked token repository
        assertFalse(revokedTokensRepository.exists(dummyHomeToken.getClaims().getId()));
        // revocation
        revocationHelper.revokeHomeToken(new Credentials(platformOwnerUsername, platformOwnerPassword), dummyHomeToken);
        // check if token is in revoked tokens repository
        assertTrue(revokedTokensRepository.exists(dummyHomeToken.getClaims().getId()));
    }

    @Test
    public void getGuestTokenSuccess() throws IOException, TimeoutException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, JWTCreationException, MalformedJWTException {
        Token token = getTokenService.getGuestToken();
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.toString());
        assertEquals(Token.Type.GUEST, Token.Type.valueOf(claimsFromToken.getTtyp()));
        assertTrue(claimsFromToken.getAtt().isEmpty());
    }

    @Test
    public void getHomeTokenByUserSuccess() throws IOException, TimeoutException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, JWTCreationException, MalformedJWTException, CertificateException, OperatorCreationException, InvalidKeyException, KeyStoreException, UnrecoverableKeyException {
        addTestUserWithClientCertificateToRepository();
        User user = userRepository.findOne(username);
        assertNotNull(user);
        Token token = tokenIssuer.getHomeToken(user, clientId);
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
    public void getHomeTokenByPlatformOwnerSuccess() throws IOException, TimeoutException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, JWTCreationException, MalformedJWTException, CertificateException, KeyStoreException, OperatorCreationException, UnrecoverableKeyException, InvalidKeyException {
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

        Platform platform = new Platform("platformInstanceId", null, null, user, null, null);
        platformRepository.save(platform);

        Token token = tokenIssuer.getHomeToken(user, federatedOAuthId);
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

    @Test(expected = JWTCreationException.class)
    public void getHomeTokenByPlatformOwnerFailureNoPlatform() throws IOException, TimeoutException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, JWTCreationException, MalformedJWTException, CertificateException, KeyStoreException, OperatorCreationException, UnrecoverableKeyException, InvalidKeyException {
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
        eu.h2020.symbiote.security.commons.Certificate cert = new Certificate(pem);
        user.getClientCertificates().put(federatedOAuthId, cert);
        userRepository.save(user);

        Token token = tokenIssuer.getHomeToken(user, federatedOAuthId);
    }

    @Test
    public void getHomeTokenSuccess() throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException, JWTCreationException {
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
    public void getForeignTokenSuccess() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, MalformedJWTException, UnrecoverableKeyException, OperatorCreationException, InvalidKeyException, JWTCreationException {

        addTestUserWithClientCertificateToRepository();
        assertNotNull(userRepository.findOne(username));
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = null;
        try {
            token = new Token(dummyPlatformAAM().doLogin(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
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
    public void getForeignTokenFailForUndefinedForeignMapping() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, MalformedJWTException, JWTCreationException, UnrecoverableKeyException, OperatorCreationException, InvalidKeyException {

        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = null;
        try {
            token = new Token(dummyPlatformAAM().doLogin(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        } catch (Exception e) {
            fail("Exception thrown");
        }
        tokenIssuer.foreignMappingRules.clear();
        tokenIssuer.getForeignToken(token);
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenFailsForHomeTokenUsedAsRequest() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, MalformedJWTException, JWTCreationException, UnrecoverableKeyException, OperatorCreationException, InvalidKeyException {

        addTestUserWithClientCertificateToRepository();
        User user = userRepository.findOne(username);
        assertNotNull(user);
        Token token = null;
        try {
            token = tokenIssuer.getHomeToken(user, clientId);
        } catch (Exception e) {
            fail("Exception thrown");
        }
        assertNotNull(token);
        getTokenService.getForeignToken(token, "", "");
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenFailsPlatformNotRegistered() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, MalformedJWTException, JWTCreationException, UnrecoverableKeyException, OperatorCreationException, InvalidKeyException {

        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = null;
        try {
            token = new Token(dummyPlatformAAM().doLogin(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        } catch (Exception e) {
            fail("Exception thrown");
        }
        assertNotNull(token);
        getTokenService.getForeignToken(token, "", "");
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenFailsPlatformHasNotCertificate() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, MalformedJWTException, JWTCreationException, UnrecoverableKeyException, OperatorCreationException, InvalidKeyException {

        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = null;
        try {
            token = new Token(dummyPlatformAAM().doLogin(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
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


}
