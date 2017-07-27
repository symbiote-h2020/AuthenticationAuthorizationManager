package eu.h2020.symbiote.security.unit;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.CoreAttributes;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.listeners.rest.AAMServices;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAMConnectionProblem;
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
    @Autowired
    private ValidationHelper validationHelper;
    @Autowired
    private TokenIssuer tokenIssuer;
    @Autowired
    private GetTokenService getTokenService;
    @Autowired
    private RevocationHelper revocationHelper;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    private AAMServices coreServicesController;

    @Bean
    DummyPlatformAAM dummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

    @Bean
    DummyPlatformAAMConnectionProblem dummyPlatformAAMWithConnectionProblem() {
        return new DummyPlatformAAMConnectionProblem();
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


    // test for revoke function
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
        revocationHelper.revoke(new Credentials(username, password), homeToken);

        // verify the user token is revoked
        assertTrue(revokedTokensRepository.exists(homeToken.getClaims().getId()));
    }

    // test for revoke function
    @Test
    public void revokeUserTokenByPlatform() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, WrongCredentialsException, NotExistingUserException, InvalidKeyException, OperatorCreationException, UnrecoverableKeyException {    // issuing dummy platform token
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
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, preferredPlatformId, csr);
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSR());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        eu.h2020.symbiote.security.commons.Certificate cert = new eu.h2020.symbiote.security.commons.Certificate(pem);

        user.getClientCertificates().put(federatedOAuthId, cert);

        userRepository.save(user);


        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" + SecurityConstants
                        .AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
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
        revocationHelper.revoke(new Credentials(platformOwnerUsername, platformOwnerPassword), dummyHomeToken);
        // check if token is in revoked tokens repository
        assertTrue(revokedTokensRepository.exists(dummyHomeToken.getClaims().getId()));
    }

    @Test
    public void getGuestTokenSuccess() throws IOException, TimeoutException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, JWTCreationException, MalformedJWTException {
        Token token = getTokenService.login();
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken().toString());
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
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken().toString());
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        Map<String, String> attributes = claimsFromToken.getAtt();
        assertEquals(UserRole.USER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        // verify that the token contains the user public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (username).getClientCertificates().get(clientId).getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = org.apache.commons.codec.binary.Base64.decodeBase64(claimsFromToken.getSpk());

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
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, federatedOAuthId, csr);
        byte[] bytes = org.apache.commons.codec.binary.Base64.decodeBase64(certRequest.getClientCSR());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        eu.h2020.symbiote.security.commons.Certificate cert = new eu.h2020.symbiote.security.commons.Certificate(pem);
        user.getClientCertificates().put(federatedOAuthId, cert);
        userRepository.save(user);

        Platform platform = new Platform("platformInstanceId", null, null, user, null);
        platformRepository.save(platform);

        Token token = tokenIssuer.getHomeToken(user, federatedOAuthId);
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken().toString());
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        Map<String, String> attributes = claimsFromToken.getAtt();
        assertEquals(UserRole.PLATFORM_OWNER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        // verify that the token contains the user public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (platformOwnerUsername).getClientCertificates().get(federatedOAuthId).getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = org.apache.commons.codec.binary.Base64.decodeBase64(claimsFromToken.getSpk());
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
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, federatedOAuthId, csr);
        byte[] bytes = org.apache.commons.codec.binary.Base64.decodeBase64(certRequest.getClientCSR());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        eu.h2020.symbiote.security.commons.Certificate cert = new Certificate(pem);
        user.getClientCertificates().put(federatedOAuthId, cert);
        userRepository.save(user);

        Token token = tokenIssuer.getHomeToken(user, federatedOAuthId);
    }


    @Test
    public void getHomeTokenSuccess() throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException {
        addTestUserWithClientCertificateToRepository();
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        Token token = null;
        try {
            token = getTokenService.login(signObject);
        } catch (Exception e) {
            fail("Exception thrown");
        }
        assertNotNull(token);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenWrongSign() throws IOException, ClassNotFoundException, CertificateException, MissingArgumentsException, WrongCredentialsException, JWTCreationException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, CryptoHelper.createKeyPair().getPrivate());
        getTokenService.login(signObject);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenWrongCredentials() throws IOException, ClassNotFoundException, CertificateException, MissingArgumentsException, WrongCredentialsException, JWTCreationException {
        SignedObject signObject = CryptoHelper.objectToSignedObject(wrongusername + "@" + clientId, userKeyPair.getPrivate());
        getTokenService.login(signObject);
    }

    @Test(expected = MissingArgumentsException.class)
    public void getHomeTokenMissingCredentials() throws IOException, ClassNotFoundException, CertificateException, MissingArgumentsException, WrongCredentialsException, JWTCreationException {
        SignedObject signObject = CryptoHelper.objectToSignedObject("@" + clientId, userKeyPair.getPrivate());
        getTokenService.login(signObject);
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
    public void getForeignTokenWithFederatedAttributesIssuedUsingProvisionedAttributesMappingListForGivenHomeToken() throws IOException,
            TimeoutException {
        /*
        // TODO attributes mapping list provisioning R3? R4?
        2. send an attribute mapping list
        3. receive a success status
        4. request foreign tokens which should be based on given tokens
        */
    }


}
