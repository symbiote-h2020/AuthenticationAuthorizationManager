package eu.h2020.symbiote.security;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.IAAMClient;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.*;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.UsersManagementService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
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
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
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
    protected final String componentId = "componentId";
    protected final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    protected final String smartSpaceOwnerUsername = "testSmartSpaceOwnerUsername";
    protected final String smartSpaceOwnerPassword = "testSmartSpaceOwnerPassword";
    protected final String platformOwnerUsername = "testPlatformOwnerUsername";
    protected final String platformOwnerPassword = "testPlatformOwnerPassword";
    protected final String recoveryMail = "null@dev.null";
    protected final String preferredSmartSpaceId = SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX + "preferredSmartSpaceId";
    protected final String smartSpaceInstanceFriendlyName = "friendlySmartSpaceName";
    protected final String smartSpaceGateWayAddress =
            "https://smartSpace.external:8101/someFancyHiddenPath/andHiddenAgain";
    protected final String smartSpaceSiteLocalAddress =
            "https://smartSpace.internal:8101/someFancyHiddenPath";
    protected final boolean exposedIIAddress = true;

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
    protected UsersManagementService usersManagementService;
    @Autowired
    protected SmartSpaceRepository smartSpaceRepository;
    protected ObjectMapper mapper = new ObjectMapper();
    protected String serverAddress;
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    protected String coreInterfaceAddress;
    @Value("${rabbit.queue.manage.user.request}")
    protected String userManagementRequestQueue;
    @Value("${rabbit.routingKey.manage.user.request}")
    protected String userManagementRequestRoutingKey;

    @Value("${rabbit.queue.manage.platform.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    protected String platformManagementRequestQueue;
    @Value("${rabbit.routingKey.manage.platform.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    protected String platformManagementRoutingKey;

    @Value("${rabbit.queue.manage.smartspace.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    protected String smartSpaceManagementRequestQueue;
    @Value("${rabbit.routingKey.manage.smartspace.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    protected String smartSpaceManagementRoutingKey;

    @Value("${rabbit.queue.manage.revocation.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    protected String revocationRequestQueue;
    @Value("${rabbit.queue.validate.request}")
    protected String validateRequestQueue;
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
    @Value("${aam.cache.componentCertificate.expireSeconds}")
    protected Long componentCertificateCacheExpirationTime;
    @Value("${aam.cache.availableAAMs.expireSeconds}")
    protected Long availableAAMsCacheExpirationTime;
    @Value("${rabbit.host}")
    private String rabbitHost;
    @Value("${rabbit.username}")
    private String rabbitUsername;
    @Value("${rabbit.password}")
    private String rabbitPassword;


    @Autowired
    private AAMServices aamServices;

    protected IAAMClient aamClient;
    @LocalServerPort
    private int port;

    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setMessageConverter(simpleMessageConverter());
        return rabbitTemplate;
    }

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
        userRepository.deleteAll();
        revokedKeysRepository.deleteAll();
        revokedTokensRepository.deleteAll();
        platformRepository.deleteAll();
        smartSpaceRepository.deleteAll();
        componentCertificatesRepository.deleteAll();
        localUsersAttributesRepository.deleteAll();
    }

    protected User createUser(String username, String password, String recoveryMail,
                              UserRole userRole) {
        return new User(username,
                passwordEncoder.encode(password),
                recoveryMail,
                new HashMap<>(),
                userRole,
                new HashMap<>(),
                new HashSet<>());
    }

    protected User savePlatformOwner() {
        User user = this.createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail,
                UserRole.SERVICE_OWNER);
        userRepository.save(user);

        return user;
    }

    protected User saveUser() {
        User user = this.createUser(appUsername, password, recoveryMail, UserRole.USER);
        userRepository.save(user);

        return user;
    }

    protected void saveTwoDifferentUsers() {
        User userOne = createUser("userOne", "Password", recoveryMail, UserRole.USER);
        User userTwo = createUser("userTwo", "Password", recoveryMail, UserRole.USER);

        userRepository.save(userOne);
        userRepository.save(userTwo);

        Platform platformOne = new Platform(platformId + "One", null, null, userOne, new Certificate(), new HashMap<>());
        Platform platformTwo = new Platform(platformId + "Two", null, null, userTwo, new Certificate(), new HashMap<>());
        platformRepository.save(platformOne);
        platformRepository.save(platformTwo);
    }

    protected void addTestUserWithClientCertificateToRepository() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            OperatorCreationException {
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), "federatedId",
                        "nullMail", UserRole.USER, new HashMap<>(), new HashMap<>()), OperationType.CREATE);


        User user = createUser(userManagementRequest.getUserDetails().getCredentials().getUsername(),
                userManagementRequest.getUserDetails().getCredentials().getPassword(),
                userManagementRequest.getUserDetails().getRecoveryMail(),
                userManagementRequest.getUserDetails().getRole());

        String cn = "CN=" + username + "@" + clientId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), userKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(userKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSRinPEMFormat());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        Certificate cert = new Certificate(pem);

        user.getClientCertificates().put(clientId, cert);
        userRepository.save(user);
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