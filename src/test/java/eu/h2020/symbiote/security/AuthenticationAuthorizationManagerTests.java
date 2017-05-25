package eu.h2020.symbiote.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.amqp.RabbitManager;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.payloads.UserDetails;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import eu.h2020.symbiote.security.repositories.RevokedCertificatesRepository;
import eu.h2020.symbiote.security.repositories.TokenRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.services.UserRegistrationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
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
public abstract class AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(AuthenticationAuthorizationManagerTests.class);
    protected final String username = "testApplicationUsername";
    protected final String password = "testApplicationPassword";
    protected final String wrongusername = "veryWrongTestApplicationUsername";
    protected final String wrongpassword = "veryWrongTestApplicationPassword";
    protected final String homeTokenValue = "home_token_from_platform_aam-" + username;
    protected final String registrationUri = "register";
    protected final String unregistrationUri = "unregister";


    @LocalServerPort
    protected int port;
    @Autowired
    protected UserRepository userRepository;
    @Autowired
    protected RabbitManager rabbitManager;
    @Autowired
    protected RegistrationManager registrationManager;
    @Autowired
    protected UserRegistrationService userRegistrationService;
    @Autowired
    protected PasswordEncoder passwordEncoder;


    // TODO rework tests to use Security Handler
    protected RestTemplate restTemplate = new RestTemplate();
    protected ObjectMapper mapper = new ObjectMapper();
    protected String serverAddress;
    @Value("${rabbit.queue.login.request}")
    protected String loginRequestQueue;
    @Value("${rabbit.queue.register.app.request}")
    protected String appRegistrationRequestQueue;
    @Value("${rabbit.queue.register.platform.request}")
    protected String platformRegistrationRequestQueue;
    @Value("${rabbit.queue.check_token_revocation.request}")
    protected String checkTokenRevocationRequestQueue;
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
    @Value("${aam.security.KEY_STORE_ALIAS}")
    protected String KEY_STORE_ALIAS;
    @Value("${aam.deployment.token.validityMillis}")
    protected Long tokenValidityPeriod;
    @Value("${aam.security.SIGNATURE_ALGORITHM}")
    protected String SIGNATURE_ALGORITHM;
    protected final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    @Value("${aam.security.KEY_PAIR_GEN_ALGORITHM}")
    protected String KEY_PAIR_GEN_ALGORITHM;
    @Value("${aam.security.CURVE_NAME}")
    protected String CURVE_NAME;
    @Autowired
    protected RevokedCertificatesRepository revokedCertificatesRepository;

    @Autowired
    protected TokenRepository tokenRepository;

    @Before
    public void setUp() throws Exception {
        // Catch the random port
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
        userRepository.deleteAll();
        revokedCertificatesRepository.deleteAll();
        tokenRepository.deleteAll();

        // Register test application user into DB
        UserRegistrationRequest userRegistrationRequest = new UserRegistrationRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials
                (username, password), "federatedId", "nullMail", UserRole.APPLICATION));
        userRegistrationService.register(userRegistrationRequest);
    }

    @Configuration
    @ComponentScan(basePackages = {"eu.h2020.symbiote.security"})
    static class ContextConfiguration {
    }

}