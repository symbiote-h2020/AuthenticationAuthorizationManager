package eu.h2020.symbiote.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.amqp.RabbitManager;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.payloads.Credentials;
import eu.h2020.symbiote.security.commons.payloads.UserDetails;
import eu.h2020.symbiote.security.commons.payloads.UserRegistrationRequest;
import eu.h2020.symbiote.security.repositories.CertificateRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.services.UserRegistrationService;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;

/**
 * AAM test suite stub with possibly shareable fields.
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
@DirtiesContext
public abstract class AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(AuthenticationAuthorizationManagerTests.class);
    protected final String foreignTokenUri = "request_foreign_token";
    protected final String checkHomeTokenRevocationUri = "check_home_token_revocation";
    protected final String username = "testApplicationUsername";
    protected final String password = "testApplicationPassword";
    protected final String wrongusername = "veryWrongTestApplicationUsername";
    protected final String wrongpassword = "veryWrongTestApplicationPassword";
    protected final String homeTokenValue = "home_token_from_platform_aam-" + username;
    protected final String tokenHeaderName = "X-Auth-Token";
    protected final String loginUri = "login";
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
    @Value("${aam.security.PV_KEY_STORE_PASSWORD}")
    protected String PV_KEY_STORE_PASSWORD;
    @Value("${aam.security.KEY_STORE_FILE_NAME}")
    protected String KEY_STORE_FILE_NAME;
    @Value("${aam.security.KEY_STORE_ALIAS}")
    protected String KEY_STORE_ALIAS;
    @Value("${aam.deployment.token.validityMillis}")
    protected Long tokenValidityPeriod;
    @Autowired
    private CertificateRepository certificateRepository;

    @Before
    public void setUp() throws Exception {
        // Catch the random port
        serverAddress = "http://localhost:" + port + "/";
        // Test rest template
        restTemplate = new RestTemplate();

        // cleanup db
        userRepository.deleteAll();
        certificateRepository.deleteAll();

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