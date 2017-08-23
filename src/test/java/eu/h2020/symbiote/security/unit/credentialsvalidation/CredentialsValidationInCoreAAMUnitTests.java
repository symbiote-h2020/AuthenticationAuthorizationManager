package eu.h2020.symbiote.security.unit.credentialsvalidation;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
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
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class CredentialsValidationInCoreAAMUnitTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(CredentialsValidationInCoreAAMUnitTests.class);
    // Leaf Certificate
    private static String applicationCertificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIB6jCCAZCgAwIBAgIEWWyv1DAKBggqhkjOPQQDAjB0MRQwEgYJKoZIhvcNAQkB\n" +
                    "FgVhQGIuYzENMAsGA1UECxMEdGVzdDENMAsGA1UEChMEdGVzdDENMAsGA1UEBxME\n" +
                    "dGVzdDENMAsGA1UECBMEdGVzdDELMAkGA1UEBhMCUEwxEzARBgNVBAMTCnBsYXRm\n" +
                    "b3JtLTEwHhcNMTcwNzE3MTIzODUxWhcNMTgwNzE3MTIzODUxWjCBhTEUMBIGCSqG\n" +
                    "SIb3DQEJARYFYUBiLmMxCzAJBgNVBAYTAklUMQ0wCwYDVQQIDAR0ZXN0MQ0wCwYD\n" +
                    "VQQHDAR0ZXN0MQ0wCwYDVQQKDAR0ZXN0MQ0wCwYDVQQLDAR0ZXN0MSQwIgYDVQQD\n" +
                    "DBthcHBsaWNhdGlvbi1wbGF0Zm9ybS0xLTEtYzEwWTATBgcqhkjOPQIBBggqhkjO\n" +
                    "PQMBBwNCAASGxfZa6ivSR4+BWBHRh94MNURAXBpBrZECvMH/rcgm8/aTHach6ncN\n" +
                    "fw8VY2RNf3l/runJOQQH/3xGEisDIY7fMAoGCCqGSM49BAMCA0gAMEUCIDrJxAet\n" +
                    "0IqR6aiJc87BS1faA8Ijl7kQnkphPOazKiXXAiEAoVHhBTNZACa4+2/0OsSg2k2P\n" +
                    "jExF7CXu6SB/rvivAXk=\n" +
                    "-----END CERTIFICATE-----\n";
    //  Intermediate Certificate (the good one)
    private static String rightSigningAAMCertificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIICBzCCAaqgAwIBAgIEW/ehcjAMBggqhkjOPQQDAgUAMEkxDTALBgNVBAcTBHRl\n" +
                    "c3QxDTALBgNVBAoTBHRlc3QxDTALBgNVBAsTBHRlc3QxGjAYBgNVBAMMEVN5bWJJ\n" +
                    "b1RlX0NvcmVfQUFNMB4XDTE3MDYxMzEwMjkxOVoXDTI3MDYxMTEwMjkxOVowdDEU\n" +
                    "MBIGCSqGSIb3DQEJARYFYUBiLmMxDTALBgNVBAsTBHRlc3QxDTALBgNVBAoTBHRl\n" +
                    "c3QxDTALBgNVBAcTBHRlc3QxDTALBgNVBAgTBHRlc3QxCzAJBgNVBAYTAlBMMRMw\n" +
                    "EQYDVQQDEwpwbGF0Zm9ybS0xMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7eSa\n" +
                    "IbqcQJsiQdfEzOZFnfUPejSJJCoTxI+vafbKWrrVRQSdKw0vV/Rddgu5IxVNqdWK\n" +
                    "lkwirWlMZXLRGqfwh6NTMFEwHwYDVR0jBBgwFoAUNiFCbRtr/vdc4oaiASrBxosU\n" +
                    "uZQwDwYDVR0TBAgwBgEB/wIBADAdBgNVHQ4EFgQUdxSdPTW56zEh0Wuqfx26J4ve\n" +
                    "QWwwDAYIKoZIzj0EAwIFAANJADBGAiEAv/MmIW8g5I6dVOjoRins750rxnt9OcpP\n" +
                    "VvOHShi5YqYCIQDRvpwyWySQ0U0LKjzob/GwqeYJ+6el8x1xbpJhs0Uweg==\n" +
                    "-----END CERTIFICATE-----\n";
    //  Intermediate Certificate (the bad one)
    private static String wrongSigningAAMCertificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIBrTCCAVOgAwIBAgIEWT/PizAKBggqhkjOPQQDAjBJMQ0wCwYDVQQHEwR0ZXN0\n" +
                    "MQ0wCwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MRowGAYDVQQDDBFTeW1iSW9U\n" +
                    "ZV9Db3JlX0FBTTAeFw0xNzA2MTMxMTQyMjVaFw0yNzA2MTMxMTQyMjVaMHQxFDAS\n" +
                    "BgkqhkiG9w0BCQEWBWFAYi5jMQ0wCwYDVQQLEwR0ZXN0MQ0wCwYDVQQKEwR0ZXN0\n" +
                    "MQ0wCwYDVQQHEwR0ZXN0MQ0wCwYDVQQIEwR0ZXN0MQswCQYDVQQGEwJQTDETMBEG\n" +
                    "A1UEAxMKcGxhdGZvcm0tMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMaODIy1\n" +
                    "sOOJdmd7stBIja4eGn9eKUEU/LVwocfiu6EW1pnZraI1Uqpu7t9CNjsFxWi/jDVg\n" +
                    "kViBAy/bg9kzocMwCgYIKoZIzj0EAwIDSAAwRQIhAIBz2MJoERVLmYxs7P0B5dCn\n" +
                    "yqWmjrYhosEiCUoVxIQVAiAwhZdM0XAeGGfTP2WsXGKFtcw/nL/gzvYSjAAGbkyx\n" +
                    "sw==\n" +
                    "-----END CERTIFICATE-----\n";
    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
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

        serverAddress = "https://localhost:" + port;

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
                preferredPlatformId, OperationType.CREATE);

        addTestUserWithClientCertificateToRepository();
    }

    @Test
    public void validateValidToken() throws
            SecurityException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            TimeoutException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "", "", "");
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
        ValidationStatus response = validationHelper.validate("tokenString", "", "", "");
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
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());

        //Introduce latency so that JWT expires
        Thread.sleep(tokenValidityPeriod + 10);

        //check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "", "", "");
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
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());

        // delete the user
        usersManagementService.delete(username);

        //check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "", "", "");
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
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());

        // add token to revoked tokens repository
        revokedTokensRepository.save(homeToken);

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "", "", "");
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
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());
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
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.REVOKED_IPK, response);
    }

    @Test
    public void validateIssuerDiffersDeploymentIdAndRelayValidation() throws
            IOException,
            ValidationException,
            TimeoutException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
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

        savePlatformOwner();

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
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.VALID, response);
    }

    @Test
    public void validateRevokedDummyCorePK() throws
            IOException,
            ValidationException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            JWTCreationException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/caam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
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
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.REVOKED_IPK, response);
    }

    @Test
    public void validateTokenFromDummyCoreByCore() throws
            IOException,
            ValidationException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            JWTCreationException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/caam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
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
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    // test for relay
    @Test
    public void validateForeignTokenIssuerNotInAvailableAAMs() throws
            IOException,
            ValidationException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
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

        // check if home token is valid
        ValidationStatus response = validationHelper.validateRemotelyIssuedToken(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateForeignTokenRequestFails() throws
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
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/conn_err/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "testaam-connerr";

        savePlatformOwner();

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
        ValidationStatus response = validationHelper.validateRemotelyIssuedToken(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.WRONG_AAM, response);
    }

    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateSuccess() throws
            ValidationException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        log.info("user: " + userCertificate.getSubjectDN());
        log.info("user sign: " + userCertificate.getIssuerDN());

        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        log.info("proper AAM: " + properAAMCert.getSubjectDN());
        log.info("proper AAM sign: " + properAAMCert.getIssuerDN());

        X509Certificate wrongAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-2-c1");
        log.info("wrong AAM: " + wrongAAMCert.getSubjectDN());
        log.info("wrong AAM sign: " + wrongAAMCert.getIssuerDN());

        log.info("root CA: " + certificationAuthorityHelper.getRootCACertificate().getSubjectDN());

        String testHomeToken = TokenIssuer.buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_1.p12", "platform-1-1-c1")
        );

        // valid remote home token chain
        assertEquals(
                ValidationStatus.VALID,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }


    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateISSMismatch() throws
            ValidationException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");

        String testHomeToken = TokenIssuer.buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                "bad_issuer", // mismatch token ISS
                properAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_1.p12", "platform-1-1-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }


    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateIPKMismatch() throws
            ValidationException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        X509Certificate wrongAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-2-c1");

        String testHomeToken = TokenIssuer.buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                "platform-1",
                wrongAAMCert.getPublicKey(), // mismatch token IPK
                getPrivateKeyFromKeystore("platform_1.p12", "platform-1-2-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }

    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateSignatureMismatch() throws
            ValidationException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");

        String testHomeToken = TokenIssuer.buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_1.p12", "platform-1-2-c1") // token signature mismatch
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }

    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateSPKMismatch() throws
            ValidationException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");

        String testHomeToken = TokenIssuer.buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                properAAMCert.getPublicKey().getEncoded(), // mismatch token SPK
                Token.Type.HOME,
                100000l,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_1.p12", "platform-1-1-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }


    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateSUBMismatch() throws
            ValidationException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");

        String testHomeToken = TokenIssuer.buildAuthorizationToken(
                "bad_token_sub", // mismatch token SUB
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_1.p12", "platform-1-1-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }

    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateChainMismatch() throws
            ValidationException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        X509Certificate wrongAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-2-c1");

        String testHomeToken = TokenIssuer.buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_1.p12", "platform-1-1-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(wrongAAMCert),
                        "")
        );
    }


    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateMissingChainElement() throws
            ValidationException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");

        String testHomeToken = TokenIssuer.buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_1.p12", "platform-1-1-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        "",
                        "")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        "",
                        "",
                        "")
        );
    }

    @Test
    public void validateRemoteForeignTokenRequestUsingCertificateSuccess() throws
            ValidationException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException, UnrecoverableKeyException {
        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        X509Certificate tokenIssuerAAMCert = getCertificateFromTestKeystore("platform_2.p12", "platform-2-1-c1");

        String testHomeToken = TokenIssuer.buildAuthorizationToken(
                "userId@clientId@platform-1",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.FOREIGN,
                100000l,
                "platform-2",
                tokenIssuerAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_2.p12", "platform-2-1-c1")
        );

        // valid remote foreign token chain
        assertEquals(
                ValidationStatus.VALID,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        CryptoHelper.convertX509ToPEM(tokenIssuerAAMCert))
        );

        // just for foreignTokenIssuerCert check check
        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        certificationAuthorityHelper.getRootCACert())
        );

    }

    @Test
    public void validateRemoteForeignTokenRequestUsingCertificateSUBMismatch() throws
            ValidationException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException, UnrecoverableKeyException {
        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        X509Certificate tokenIssuerAAMCert = getCertificateFromTestKeystore("platform_2.p12", "platform-2-1-c1");

        String testHomeToken = TokenIssuer.buildAuthorizationToken(
                "userId@clientId@wrong-platform-id",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.FOREIGN,
                100000l,
                "platform-2",
                tokenIssuerAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_2.p12", "platform-2-1-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        CryptoHelper.convertX509ToPEM(tokenIssuerAAMCert))
        );

    }

    @Test
    public void validateRemoteForeignTokenRequestUsingCertificateMissingTokenIssuerCert() throws
            ValidationException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException, UnrecoverableKeyException {
        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        X509Certificate tokenIssuerAAMCert = getCertificateFromTestKeystore("platform_2.p12", "platform-2-1-c1");

        String testHomeToken = TokenIssuer.buildAuthorizationToken(
                "userId@clientId@platform-1",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.FOREIGN,
                100000l,
                "platform-2",
                tokenIssuerAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_2.p12", "platform-2-1-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }


    @Test
    public void rootCAChainValidationSuccess() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {
        assertTrue(validationHelper.isForeignTokenIssuerCertificateChainTrusted(certificationAuthorityHelper.getRootCACert()));
    }

    @Test
    public void validateCertificateChainSuccess() throws
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException {
        assertTrue(validationHelper.isClientCertificateChainTrusted(rightSigningAAMCertificatePEM, applicationCertificatePEM));
    }

    @Test
    public void validateCertificateChainFailure() throws
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException {
        assertFalse(validationHelper.isClientCertificateChainTrusted(wrongSigningAAMCertificatePEM, applicationCertificatePEM));
    }


    private X509Certificate getCertificateFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
    }

    public PrivateKey getPrivateKeyFromKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (PrivateKey) pkcs12Store.getKey(certificateAlias, PV_KEY_PASSWORD.toCharArray());
    }
}
