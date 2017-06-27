package eu.h2020.symbiote.security.unit;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.IOldSecurityHandler;
import eu.h2020.symbiote.security.SecurityHandler;
import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.commons.Platform;
import eu.h2020.symbiote.security.commons.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.commons.TokenManager;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import eu.h2020.symbiote.security.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.payloads.*;
import eu.h2020.symbiote.security.rest.CertificateRequest;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAMConnectionProblem;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
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
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import static io.jsonwebtoken.impl.crypto.RsaProvider.generateKeyPair;
import static org.junit.Assert.*;

/**
 * Test suite for generic AAM functionality irrelevant to actual deployment type (Core or Platform)
 *
 * @author Piotr Kicki (PSNC)
 */
@TestPropertySource("/core.properties")
public class AAMUnitTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(AAMUnitTests.class);
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
    @Value("${aam.security.SIGNATURE_ALGORITHM}")
    protected String SIGNATURE_ALGORITHM;
    @Value("${aam.security.KEY_PAIR_GEN_ALGORITHM}")
    protected String KEY_PAIR_GEN_ALGORITHM;
    @Value("${aam.security.CURVE_NAME}")
    protected String CURVE_NAME;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    @Autowired
    private TokenManager tokenManager;
    private RpcClient platformRegistrationOverAMQPClient;
    private UserDetails platformOwnerUserDetails;
    private PlatformRegistrationRequest platformRegistrationOverAMQPRequest;

    @Bean
    DummyPlatformAAM getDummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

    @Bean
    DummyPlatformAAMConnectionProblem getDummyPlatformAAMConnectionProblem() {
        return new DummyPlatformAAMConnectionProblem();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

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

    @Test
    public void applicationInternalRegistrationSuccess() throws SecurityException {
        String appUsername = "NewApplication";

        // verify that app is not in the repository
        User registeredUser = userRepository.findOne(appUsername);
        assertNull(registeredUser);

            /*
             XXX federated Id and recovery mail are required for Test & Core AAM but not for Platform AAM
             */
        // register new application to db
        UserRegistrationRequest userRegistrationRequest = new UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials
                (appUsername, "NewPassword"), "nullId", "nullMail", UserRole.APPLICATION));
        UserRegistrationResponse userRegistrationResponse = userRegistrationService.register
                (userRegistrationRequest);

        // verify that app really is in repository
        registeredUser = userRepository.findOne(appUsername);
        assertNotNull(registeredUser);
        assertEquals(UserRole.APPLICATION, registeredUser.getRole());

        // verify that the server returns certificate & privateKey
        assertNotNull(userRegistrationResponse.getUserCertificate());
        assertNotNull(userRegistrationResponse.getUserPrivateKey());

        // TODO verify that released certificate has no CA property
        //assertFalse(registeredUser.getCertificate().getX509().getExtensionValue(new ASN1ObjectIdentifier
        // ("2.5.29.19"),));
    }

    @Test
    public void applicationInternalUnregistrationSuccess() throws SecurityException, CertificateException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // unregister the user
        userRegistrationService.unregister(username);
        log.debug("User successfully unregistered!");

        // verify that app is not anymore in the repository
        assertFalse(userRepository.exists(username));

        // verify that the user certificate was indeed revoked
        assertTrue(revokedKeysRepository.exists(username));
        SubjectsRevokedKeys revokedKeys = revokedKeysRepository.findOne(username);
        assertNotNull(revokedKeys);
        assertTrue(revokedKeys.getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(
                user.getCertificate().getX509().getPublicKey().getEncoded())));
    }

    @Test
    public void certificateCreationAndVerification() throws Exception {
        // Generate certificate for given application username (ie. "Daniele")
        KeyPair keyPair = registrationManager.createKeyPair();
        X509Certificate cert = registrationManager.createECCert("Daniele", keyPair.getPublic());

        // retrieves Platform AAM ("Daniele"'s certificate issuer) public key from keystore in order to verify
        // "Daniele"'s certificate
        cert.verify(registrationManager.getAAMPublicKey());

        // also check time validity
        cert.checkValidity(new Date());
    }

    @Test
    public void generateCertificateFromCSRSuccess() throws OperatorCreationException, CertificateException,
            UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException,
            InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        KeyPairGenerator g = KeyPairGenerator.getInstance(KEY_PAIR_GEN_ALGORITHM, PROVIDER_NAME);
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(CURVE_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = g.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        X509Certificate cert = registrationManager.generateCertificateFromCSR(csr);
        assertNotNull(cert);
    }

    @Test
    public void generateCertificateFromCSRCorrectSubjectTest() throws OperatorCreationException,
            CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchProviderException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        KeyPairGenerator g = KeyPairGenerator.getInstance(KEY_PAIR_GEN_ALGORITHM, PROVIDER_NAME);
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(CURVE_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = g.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        X509Certificate cert = registrationManager.generateCertificateFromCSR(csr);
        assertEquals(new X500Name(cert.getSubjectDN().getName()), csr.getSubject());
    }

    @Test
    public void generateCertificateFromCSRPublicKeyTest() throws OperatorCreationException, CertificateException,
            UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException,
            InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        KeyPairGenerator g = KeyPairGenerator.getInstance(KEY_PAIR_GEN_ALGORITHM, PROVIDER_NAME);
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(CURVE_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = g.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        X509Certificate cert = registrationManager.generateCertificateFromCSR(csr);
        assertEquals(keyPair.getPublic(), cert.getPublicKey());
    }

    @Test
    public void generatedCertificateCreationAndVerification() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance(KEY_PAIR_GEN_ALGORITHM, PROVIDER_NAME);
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(CURVE_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = g.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        X509Certificate cert = registrationManager.generateCertificateFromCSR(csr);
        cert.verify(registrationManager.getAAMPublicKey());

        cert.checkValidity(new Date());
    }

    @Test
    public void validateWrongToken() throws SecurityException, CertificateException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        //check if home token revoked properly
        ValidationStatus response = tokenManager.validate("tokenString");
        assertEquals(ValidationStatus.UNKNOWN, response);
    }

    @Test
    public void validateExpiredToken() throws SecurityException, CertificateException, InterruptedException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenManager.createHomeToken(user);

        //Introduce latency so that JWT expires
        Thread.sleep(tokenValidityPeriod + 1000);

        //check if home token revoked properly
        ValidationStatus response = tokenManager.validate(homeToken.getToken());
        assertEquals(ValidationStatus.EXPIRED_TOKEN, response);
    }

    @Test
    public void validateAfterUnregistrationBySPK() throws SecurityException, CertificateException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenManager.createHomeToken(user);

        // unregister the user
        userRegistrationService.unregister(username);
        //log.debug("User successfully unregistered!");

        //check if home token revoked properly
        ValidationStatus response = tokenManager.validate(homeToken.getToken());
        assertEquals(ValidationStatus.REVOKED_SPK, response);
    }

    @Test
    public void validateRevokedToken() throws SecurityException, CertificateException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenManager.createHomeToken(user);

        // add token to repository
        revokedTokensRepository.save(homeToken);

        // check if home token revoked properly
        ValidationStatus response = tokenManager.validate(homeToken.getToken());
        assertEquals(ValidationStatus.REVOKED_TOKEN, response);
    }

    @Test
    public void validateRevokedIPK() throws SecurityException, CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenManager.createHomeToken(user);
        String issuer = JWTEngine.getClaims(homeToken.getToken()).getIssuer();

        // verify the issuer keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(issuer));

        // insert CoreAAM public key into set to be revoked
        Certificate coreCertificate = new Certificate(registrationManager.getAAMCert());
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(coreCertificate.getX509().getPublicKey().getEncoded()));

        // adding key to revoked repository
        SubjectsRevokedKeys subjectsRevokedKeys = new SubjectsRevokedKeys(issuer, keySet);
        revokedKeysRepository.save(subjectsRevokedKeys);

        // check if home token revoked properly
        ValidationStatus response = tokenManager.validate(homeToken.getToken());
        assertEquals(ValidationStatus.REVOKED_IPK, response);
    }

    @Test
    public void validateIssuerDiffersDeploymentIdAndRelayValidation() throws IOException, TimeoutException,
            NoSuchProviderException, KeyStoreException, CertificateException,
            NoSuchAlgorithmException, ValidationException {
        // issuing dummy platform token
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

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
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // check if validation will be relayed to appropriate issuer
        ValidationStatus response = tokenManager.validate(dummyHomeToken.getToken());
        assertEquals(ValidationStatus.VALID, response);
    }

    @Test
    public void validateRevokedDummyCorePK() throws IOException, TimeoutException,
            NoSuchProviderException, KeyStoreException, CertificateException,
            NoSuchAlgorithmException, ValidationException {
        // issuing dummy platform token
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/caam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "core-2";
        //inject platform PEM Certificate to the database
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/core.p12"), "1234567".toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(platformId);
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        String dummyPlatformAAMPEMCertString = signedCertificatePEMDataStringWriter.toString();

        String issuer = JWTEngine.getClaims(dummyHomeToken.getToken()).getIssuer();

        // verify the issuer keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(issuer));

        // insert DummyPlatformAAM public key into set to be revoked
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(
                registrationManager.convertPEMToX509(dummyPlatformAAMPEMCertString).getPublicKey().getEncoded()));

        // adding key to revoked repository
        SubjectsRevokedKeys subjectsRevokedKeys = new SubjectsRevokedKeys(issuer, keySet);
        revokedKeysRepository.save(subjectsRevokedKeys);

        // check if platform token is not revoked
        ValidationStatus response = tokenManager.validate(dummyHomeToken.getToken());
        assertEquals(ValidationStatus.REVOKED_IPK, response);
    }

    @Test
    public void validateTokenFromDummyCoreByCore() throws IOException, TimeoutException,
            NoSuchProviderException, KeyStoreException, CertificateException,
            NoSuchAlgorithmException, ValidationException {
        // issuing dummy platform token
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/caam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "core-2";
        //inject platform PEM Certificate to the database
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/core.p12"), "1234567".toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(platformId);
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();

        // check if platform token is not revoked
        ValidationStatus response = tokenManager.validate(dummyHomeToken.getToken());
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    // test for relay
    @Test
    public void validateFederatedTokenIssuerNotInAvailableAAMs() throws SecurityException, CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
            IOException {
        // issuing dummy platform token
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token revoked properly
        ValidationStatus response = tokenManager.validateFederatedToken(dummyHomeToken.getToken());
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateFederatedTokenRequestFails() throws IOException, TimeoutException,
            NoSuchProviderException, KeyStoreException, CertificateException,
            NoSuchAlgorithmException, ValidationException {
        // issuing dummy platform token
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/conn_err/paam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "testaam-connerr";
        // registering the platform to the Core AAM so it will be available for token revocation
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(platformId);
        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress(serverAddress + "/test/conn_err");

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
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // check if validation will fail due to for example connection problems
        ValidationStatus response = tokenManager.validateFederatedToken(dummyHomeToken.getToken());
        assertEquals(ValidationStatus.WRONG_AAM, response);
    }

    @Ignore("TODO")
    @Test
    public void getCertificateWrongCredentialsFailure() throws OperatorCreationException, IOException {
        UserRegistrationRequest request= new UserRegistrationRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(username, password), clientId, "", UserRole.APPLICATION));
        ResponseEntity<UserRegistrationResponse> response = restTemplate.postForEntity(serverAddress +
                registrationUri, request, UserRegistrationResponse.class);

        IOldSecurityHandler securityHandler;
        String symbioteCoreInterfaceAddress = "http://localhost:58419";
        securityHandler = new SecurityHandler(symbioteCoreInterfaceAddress);

        KeyPair pair = generateKeyPair();
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), pair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(pair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        String csrString = Base64.getEncoder().encodeToString(csr.getEncoded());
        try {
            ResponseEntity<CertificateRequest> response2 = restTemplate.postForEntity(serverAddress + "/getCertificate",
                    new CertificateRequest(new AAM(symbioteCoreInterfaceAddress, "A test platform aam", "SomePlatformAAM", new Certificate()),
                            username,wrongpassword,clientId,csrString), CertificateRequest.class);
        } catch (Exception e) {
            assertEquals(WrongCredentialsException.class, e.getClass());
        }
    }

    @Ignore("TODO")
    @Test
    public void getCertificateRevokedKeyFailure() throws OperatorCreationException, IOException, InterruptedException {
        UserRegistrationRequest request= new UserRegistrationRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(username, password), clientId, "", UserRole.APPLICATION));
        ResponseEntity<UserRegistrationResponse> response = restTemplate.postForEntity(serverAddress +
                registrationUri, request, UserRegistrationResponse.class);

        IOldSecurityHandler securityHandler;
        String symbioteCoreInterfaceAddress = "http://localhost:58419";
        securityHandler = new SecurityHandler(symbioteCoreInterfaceAddress);

        KeyPair pair = generateKeyPair();
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), pair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(pair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        String csrString = Base64.getEncoder().encodeToString(csr.getEncoded());
        ResponseEntity<CertificateRequest> response2 = restTemplate.postForEntity(serverAddress + "/getCertificate",
                new CertificateRequest(new AAM(symbioteCoreInterfaceAddress, "A test platform aam", "SomePlatformAAM", new Certificate()),
                        username, password, clientId, csrString), CertificateRequest.class);

        Thread.sleep(tokenValidityPeriod+1000);

        try{
            ResponseEntity<CertificateRequest> response3 = restTemplate.postForEntity(serverAddress + "/getCertificate",
                    new CertificateRequest(new AAM(symbioteCoreInterfaceAddress, "A test platform aam", "SomePlatformAAM", new Certificate()),
                            username,password,clientId,csrString), CertificateRequest.class);
        } catch (Exception e) {
            assertEquals(InvalidKeyException.class, e.getClass());
        }
    }

    @Test
    public void revokeUserPublicKey() throws SecurityException, CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);

        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // revocation
        tokenManager.revoke(new Credentials(username, password), user.getCertificate());

        // verify the user keys are revoked
        assertTrue(revokedKeysRepository.exists(username));
    }

    @Test
    public void revokeUserToken() throws SecurityException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // acquiring valid token
        Token homeToken = tokenManager.createHomeToken(user);

        // verify the user token is not yet revoked
        assertFalse(revokedTokensRepository.exists(homeToken.getClaims().getId()));

        // revocation
        tokenManager.revoke(new Credentials(username, password), homeToken);

        // verify the user token is revoked
        assertTrue(revokedTokensRepository.exists(homeToken.getClaims().getId()));
    }

    @Test
    public void revokeUserTokenByPlatform() throws ValidationException, IOException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, WrongCredentialsException, NotExistingUserException, InvalidKeyException {
        // issuing dummy platform token
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" + AAMConstants
                        .AAM_LOGIN,
                new Credentials(username, password), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(AAMConstants.TOKEN_HEADER_NAME).get(0));

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
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        assertFalse(revokedTokensRepository.exists(dummyHomeToken.getClaims().getId()));

        tokenManager.revoke(new Credentials(platformOwnerUsername, platformOwnerPassword), dummyHomeToken);

        assertTrue(revokedTokensRepository.exists(dummyHomeToken.getClaims().getId()));

    }

}