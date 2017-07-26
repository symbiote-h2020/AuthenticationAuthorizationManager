package eu.h2020.symbiote.security.unit.validation;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class ValidationUnitTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(ValidationUnitTests.class);

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
    @Autowired
    protected UserRepository userRepository;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    @Autowired
    private ValidationHelper validationHelper;
    @LocalServerPort
    private int port;
    @Autowired
    private TokenIssuer tokenIssuer;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;

    @Bean
    DummyPlatformAAM getDummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        serverAddress = "https://localhost:" + port + SecurityConstants.AAM_PUBLIC_PATH;

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        // Test rest template
        restTemplate = new RestTemplate();

        // cleanup db
        //userRepository.deleteAll();
        revokedKeysRepository.deleteAll();
        revokedTokensRepository.deleteAll();
        platformRepository.deleteAll();
        userKeyPair = CryptoHelper.createKeyPair();

        // platform registration useful
        platformRegistrationOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformRegistrationRequestQueue, 5000);
        platformOwnerUserCredentials = new Credentials(platformOwnerUsername, platformOwnerPassword);
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId);

    }

    @Test
    public void validateValidToken() throws SecurityException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, TimeoutException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId);

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "");
        assertEquals(ValidationStatus.VALID, response);
    }

    @Test
    public void validateWrongToken() throws SecurityException, CertificateException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        //check if home token is valid
        ValidationStatus response = validationHelper.validate("tokenString", "");
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
        Token homeToken = tokenIssuer.getHomeToken(user, clientId);

        //Introduce latency so that JWT expires
        Thread.sleep(tokenValidityPeriod + 1000);

        //check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "");
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
        Token homeToken = tokenIssuer.getHomeToken(user, clientId);

        // unregister the user
        usersManagementService.unregister(username);

        //check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "");
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
        Token homeToken = tokenIssuer.getHomeToken(user, clientId);

        // add token to revoked tokens repository
        revokedTokensRepository.save(homeToken);

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "");
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
        Token homeToken = tokenIssuer.getHomeToken(user, clientId);
        String issuer = JWTEngine.getClaims(homeToken.getToken()).getIssuer();

        // verify the issuer keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(issuer));

        // insert CoreAAM public key into set to be revoked
        Certificate coreCertificate = new Certificate(certificationAuthorityHelper.getAAMCert());
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(coreCertificate.getX509().getPublicKey().getEncoded()));

        // adding key to revoked repository
        SubjectsRevokedKeys subjectsRevokedKeys = new SubjectsRevokedKeys(issuer, keySet);
        revokedKeysRepository.save(subjectsRevokedKeys);

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "");
        assertEquals(ValidationStatus.REVOKED_IPK, response);
    }

    @Test
    public void validateIssuerDiffersDeploymentIdAndRelayValidation() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        // issuing dummy platform token
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" +
                        SecurityConstants
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
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // check if validation will be relayed to appropriate issuer
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "");
        assertEquals(ValidationStatus.VALID, response);
    }

    @Test
    public void validateRevokedDummyCorePK() throws IOException, ValidationException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        // issuing dummy platform token
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/caam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

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
                CryptoHelper.convertPEMToX509(dummyPlatformAAMPEMCertString).getPublicKey().getEncoded()));

        // adding key to revoked repository
        SubjectsRevokedKeys subjectsRevokedKeys = new SubjectsRevokedKeys(issuer, keySet);
        revokedKeysRepository.save(subjectsRevokedKeys);

        // check if platform token is is valid
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "");
        assertEquals(ValidationStatus.REVOKED_IPK, response);
    }

    @Test
    public void validateTokenFromDummyCoreByCore() throws IOException, ValidationException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        // issuing dummy platform token
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/caam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "core-2";
        //inject platform PEM Certificate to the database
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/core.p12"), "1234567".toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(platformId);
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();

        // check if platform token is valid
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    // test for relay
    @Test
    public void validateFederatedTokenIssuerNotInAvailableAAMs() throws IOException, ValidationException, CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException {
        // issuing dummy platform token
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token is valid
        ValidationStatus response = validationHelper.validateForeignToken(dummyHomeToken.getToken(), "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateFederatedTokenRequestFails() throws IOException, ValidationException, TimeoutException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
        // issuing dummy platform token
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/conn_err/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

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
        ValidationStatus response = validationHelper.validateForeignToken(dummyHomeToken.getToken(), "");
        assertEquals(ValidationStatus.WRONG_AAM, response);
    }


    @Test
    @Ignore("TODO missing trust chain validation")
    public void validateFederatedTokenRequestInIntranetUsingProvidedCertificate() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        // issuing dummy platform token
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/conn_err/paam" + SecurityConstants
                        .AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

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

        // check if validation will use certificate before relay
        ValidationStatus response = validationHelper.validateForeignToken(dummyHomeToken.getToken(), "certificate");
        assertEquals(ValidationStatus.VALID, response);
    }
}

