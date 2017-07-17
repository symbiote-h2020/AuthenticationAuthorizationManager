package eu.h2020.symbiote.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.interfaces.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.listeners.amqp.RabbitManager;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.RevokedTokensRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.services.UsersManagementService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * AAM test suite stub with possibly shareable fields.
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
@DirtiesContext
public abstract class AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(AbstractAAMTestSuite.class);
    protected final String username = "testApplicationUsername";
    protected final String password = "testApplicationPassword";
    protected final String wrongusername = "veryWrongTestApplicationUsername";
    protected final String wrongpassword = "veryWrongTestApplicationPassword";
    protected final String registrationUri = "/register";
    protected final String unregistrationUri = "/unregister";
    protected final String usernameWithAt = "test@";
    protected final String clientId = "clientId";
    @Autowired
    protected UserRepository userRepository;
    @Autowired
    protected RevokedTokensRepository revokedTokensRepository;
    @Autowired
    protected RevokedKeysRepository revokedKeysRepository;
    @Autowired
    protected PlatformRepository platformRepository;
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
    @Value("${rabbit.queue.register.user.request}")
    protected String userRegistrationRequestQueue;
    @Value("${rabbit.queue.register.platform.request}")
    protected String platformRegistrationRequestQueue;
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
    @LocalServerPort
    private int port;

    @Before
    public void setUp() throws Exception {
        // Catch the random port
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
        userRepository.deleteAll();
        revokedKeysRepository.deleteAll();
        revokedTokensRepository.deleteAll();
        platformRepository.deleteAll();


        // Register test user user into DB
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials
                (username, password), "federatedId", "nullMail", UserRole.USER));
        usersManagementService.register(userManagementRequest);
    }

    @Configuration
    @ComponentScan(basePackages = {"eu.h2020.symbiote.security"})
    static class ContextConfiguration {
    }

}