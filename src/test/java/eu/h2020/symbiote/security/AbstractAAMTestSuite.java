package eu.h2020.symbiote.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.listeners.amqp.RabbitManager;
import eu.h2020.symbiote.security.repositories.*;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.UsersManagementService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;

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

/**
 * AAM test suite stub with possibly shareable fields.
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
public abstract class AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(AbstractAAMTestSuite.class);
    protected final String username = "testApplicationUsername";
    protected final String password = "testApplicationPassword";
    protected final String wrongusername = "veryWrongTestApplicationUsername";
    protected final String wrongpassword = "veryWrongTestApplicationPassword";
    protected final String usernameWithAt = "test@";
    protected final String appUsername = "NewApplication";
    protected final String clientId = "clientId";
    protected final String wrongClientId = "wrongClientId";
    protected final String platformId = "testPlatformId";
    protected final String componentId = "componentId";
    protected final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    protected final String platformOwnerUsername = "testPlatformOwnerUsername";
    protected final String platformOwnerPassword = "testPlatformOwnerPassword";
    protected final String recoveryMail = "null@dev.null";
    protected KeyPair userKeyPair;
    @Autowired
    protected FederationRulesRepository federationRulesRepository;
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
    protected RabbitManager rabbitManager;
    @Autowired
    protected CertificationAuthorityHelper certificationAuthorityHelper;
    @Autowired
    protected UsersManagementService usersManagementService;
    protected RestTemplate restTemplate = new RestTemplate();
    protected ObjectMapper mapper = new ObjectMapper();
    protected String serverAddress;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    protected String coreInterfaceAddress;
    @Value("${rabbit.queue.getHomeToken.request}")
    protected String loginRequestQueue;
    @Value("${rabbit.queue.manage.user.request}")
    protected String userManagementRequestQueue;
    @Value("${rabbit.queue.manage.platform.request}")
    protected String platformManagementRequestQueue;
    @Value("${rabbit.queue.manage.revocation.request}")
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
    protected AAMClient AAMClient;
    @LocalServerPort
    private int port;

    @Before
    public void setUp() throws Exception {
        // Catch the random port
        serverAddress = "https://localhost:" + port;
        AAMClient = new AAMClient(serverAddress);

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
        userKeyPair = CryptoHelper.createKeyPair();
        // Test rest template
        restTemplate = new RestTemplate();

        // cleanup db
        userRepository.deleteAll();
        revokedKeysRepository.deleteAll();
        revokedTokensRepository.deleteAll();
        platformRepository.deleteAll();
        componentCertificatesRepository.deleteAll();
        localUsersAttributesRepository.deleteAll();
    }

    protected User savePlatformOwner() {
        User user = new User();
        user.setUsername(platformOwnerUsername);
        user.setPasswordEncrypted(passwordEncoder.encode(platformOwnerPassword));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(user);

        return user;
    }

    protected User saveUser() {
        User user = new User();
        user.setUsername(appUsername);
        user.setPasswordEncrypted(passwordEncoder.encode(password));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.USER);
        userRepository.save(user);

        return user;
    }

    protected void addTestUserWithClientCertificateToRepository() throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException, OperatorCreationException, UnrecoverableKeyException, InvalidKeyException {
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password), "federatedId",
                        "nullMail", UserRole.USER, new HashMap<>(), new HashMap<>()), OperationType.CREATE);

        User user = new User();
        user.setRole(userManagementRequest.getUserDetails().getRole());
        user.setUsername(userManagementRequest.getUserDetails().getCredentials().getUsername());
        user.setPasswordEncrypted(passwordEncoder.encode(userManagementRequest.getUserDetails().getCredentials().getPassword()));
        user.setRecoveryMail(userManagementRequest.getUserDetails().getRecoveryMail());

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

}