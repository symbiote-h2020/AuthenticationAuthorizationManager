package eu.h2020.symbiote.security;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.IAAMClient;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.*;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.SignCertificateRequestService;
import eu.h2020.symbiote.security.services.UsersManagementService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.amqp.support.converter.SimpleMessageConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;

/**
 * AAM test suite stub with possibly shareable fields.
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
public abstract class AbstractAAMTestSuite {

    protected final String username = "testApplicationUsername";
    protected final String password = "testApplicationPassword";
    protected final String wrongUsername = "veryWrongTestApplicationUsername";
    protected final String wrongPassword = "veryWrongTestApplicationPassword";
    protected final String usernameWithAt = "test@";
    protected final String appUsername = "NewApplication";
    protected final String clientId = "clientId";
    protected final String wrongClientId = "wrongClientId";
    protected final String platformId = "test-PlatformId";
    protected final String platformInstanceFriendlyName = "platformInstanceFriendlyName";
    protected final String componentId = "componentId";
    protected final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    protected final String smartSpaceOwnerUsername = "testSmartSpaceOwnerUsername";
    protected final String smartSpaceOwnerPassword = "testSmartSpaceOwnerPassword";
    protected final String platformOwnerUsername = "testPlatformOwnerUsername";
    protected final String platformOwnerPassword = "testPlatformOwnerPassword";
    protected final String recoveryMail = "null@dev.null";
    protected final String preferredSmartSpaceId = SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX + "preferredSmartSpaceId";
    protected final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
    protected final String smartSpaceInstanceFriendlyName = "friendlySmartSpaceName";
    protected final String smartSpaceGateWayAddress =
            "https://smartSpace.external:8101/someFancyHiddenPath/andHiddenAgain";
    protected final String smartSpaceSiteLocalAddress =
            "https://smartSpace.internal:8101/someFancyHiddenPath";
    protected final boolean isExposingSiteLocalAddress = true;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();
    protected KeyPair userKeyPair;
    @Autowired
    protected FederationsRepository federationsRepository;
    @Autowired
    protected LocalUsersAttributesRepository localUsersAttributesRepository;
    @Autowired
    protected UserRepository userRepository;
    @Autowired
    protected RevokedTokensRepository revokedTokensRepository;
    @Autowired
    protected RevokedKeysRepository revokedKeysRepository;
    @Autowired
    protected PlatformRepository platformRepository;
    @Autowired
    protected ComponentCertificatesRepository componentCertificatesRepository;
    @Autowired
    protected CertificationAuthorityHelper certificationAuthorityHelper;
    @Autowired
    protected SignCertificateRequestService signCertificateRequestService;
    @Autowired
    protected UsersManagementService usersManagementService;
    @Autowired
    protected SmartSpaceRepository smartSpaceRepository;
    @Autowired
    protected RevokedRemoteTokensRepository revokedRemoteTokensRepository;

    protected ObjectMapper mapper = new ObjectMapper();
    protected String serverAddress;
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    protected String coreInterfaceAddress;

    @Value("${aam.deployment.owner.username}")
    protected String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    protected String AAMOwnerPassword;
    @Value("${aam.security.KEY_STORE_PASSWORD}")
    protected String KEY_STORE_PASSWORD;
    @Value("${aam.security.PV_KEY_PASSWORD}")
    protected String PV_KEY_PASSWORD;
    @Value("${aam.security.KEY_STORE_FILE_NAME}")
    protected String KEY_STORE_FILE_NAME;
    @Value("${aam.security.CERTIFICATE_ALIAS}")
    protected String CERTIFICATE_ALIAS;
    @Value("${aam.deployment.token.validityMillis}")
    protected Long tokenValidityPeriod;
    @Value("${aam.cache.validToken.expireMillis}")
    protected Long validTokenCacheExpirationTime;

    @Autowired
    private AAMServices aamServices;

    protected IAAMClient aamClient;
    @LocalServerPort
    private int port;

    @Bean
    public SimpleMessageConverter simpleMessageConverter() {
        return new SimpleMessageConverter();
    }

    @BeforeClass
    public static void setupSuite() throws Exception {
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
    }

    @Before
    public void setUp() throws Exception {
        // Catch the random port
        serverAddress = "https://localhost:" + port;
        ReflectionTestUtils.setField(aamServices, "localAAMUrl", serverAddress);
        aamClient = new AAMClient(serverAddress);
        userKeyPair = CryptoHelper.createKeyPair();

        // cleanup db
        componentCertificatesRepository.deleteAll();
        federationsRepository.deleteAll();
        localUsersAttributesRepository.deleteAll();
        platformRepository.deleteAll();
        revokedKeysRepository.deleteAll();
        revokedRemoteTokensRepository.deleteAll();
        revokedTokensRepository.deleteAll();
        smartSpaceRepository.deleteAll();
        userRepository.deleteAll();
    }

    protected User createUser(String username,
                              String password,
                              String recoveryMail,
                              UserRole userRole,
                              AccountStatus status) {
        return new User(username,
                passwordEncoder.encode(password),
                recoveryMail,
                new HashMap<>(),
                userRole,
                status,
                new HashMap<>(),
                new HashSet<>(),
                true,
                false);
    }

    protected User savePlatformOwner() {
        User user = this.createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail,
                UserRole.SERVICE_OWNER, AccountStatus.ACTIVE);
        userRepository.save(user);

        return user;
    }

    protected User saveUser() {
        User user = this.createUser(appUsername, password, recoveryMail, UserRole.USER, AccountStatus.ACTIVE);
        userRepository.save(user);

        return user;
    }

    protected User saveNewUser() {
        User user = this.createUser(appUsername, password, recoveryMail, UserRole.USER, AccountStatus.NEW);
        userRepository.save(user);
        return user;
    }


    protected void addTestUserWithClientCertificateToRepository() {

        try {
            User user = createUser(username, password, recoveryMail, UserRole.USER, AccountStatus.ACTIVE);
            userRepository.save(user);
            String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), username, clientId, userKeyPair);
            CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csr);
            String pem = signCertificateRequestService.signCertificateRequest(certRequest);

            user.getClientCertificates().put(clientId, new Certificate(pem));
            userRepository.save(user);
        } catch (SecurityException | CertificateException | IOException e) {
            e.printStackTrace();
        }
    }

    @Configuration
    @ComponentScan(basePackages = {"eu.h2020.symbiote.security"})
    static class ContextConfiguration {
    }

    public X509Certificate getCertificateFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
    }

    public PrivateKey getPrivateKeyTestFromKeystore(String keyStoreName, String certificateAlias) throws
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

    public String convertObjectToJson(Object obj) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.INDENT_OUTPUT, false);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        return mapper.writeValueAsString(obj);
    }

}