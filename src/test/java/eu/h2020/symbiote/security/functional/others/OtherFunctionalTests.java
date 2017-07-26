package eu.h2020.symbiote.security.functional.others;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.*;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertEquals;

/**
 * Test suite for Core AAM deployment scenarios.
 */
@TestPropertySource("/core.properties")
public class OtherFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(OtherFunctionalTests.class);
    private final String coreAppUsername = "testCoreAppUsername";
    private final String coreAppPassword = "testCoreAppPassword";
    private final String recoveryMail = "null@dev.null";
    private final String federatedOAuthId = "federatedOAuthId";
    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
    private final String platformOwnerUsername = "testPlatformOwnerUsername";
    private final String platformOwnerPassword = "testPlatormOwnerPassword";
    private final String platformId = "testPlatformId";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    private KeyPair platformOwnerKeyPair;
    private UserManagementRequest appUserManagementRequest;
    private RpcClient appRegistrationClient;
    private UserDetails appUserDetails;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    @Autowired
    private PlatformRepository platformRepository;

    @Autowired
    private ValidationHelper validationHelper;
    @Autowired
    private TokenIssuer tokenIssuer;

    @Bean
    DummyPlatformAAM getDummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // db cleanup
        platformRepository.deleteAll();
        userRepository.deleteAll();

        // user registration useful
        appRegistrationClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                userRegistrationRequestQueue, 5000);
        appUserDetails = new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.USER);
        appUserManagementRequest = new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), appUserDetails);

        //user registration useful
        User user = new User();
        user.setUsername(platformOwnerUsername);
        user.setPasswordEncrypted(passwordEncoder.encode(platformOwnerPassword));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(user);

        // platform registration useful
        platformRegistrationOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformRegistrationRequestQueue, 5000);
        platformOwnerUserCredentials = new Credentials(user.getUsername(), user.getPasswordEncrypted());
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId);
        platformOwnerKeyPair = CryptoHelper.createKeyPair();

    }

    /**
     * Features: Core AAM  providing list of available security entry points
     * CommunicationType REST
     */
    @Test
    public void getAvailableAAMsOverRESTWithNoRegisteredPlatforms() throws NoSuchAlgorithmException,
            CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        ResponseEntity<Map<String, AAM>> response = restTemplate.exchange(serverAddress + SecurityConstants
                .AAM_GET_AVAILABLE_AAMS, HttpMethod.GET, null, new ParameterizedTypeReference<Map<String, AAM>>() {
        });
        assertEquals(HttpStatus.OK, response.getStatusCode());

        // verify the body
        Map<String, AAM> aams = response.getBody();
        // there should be only core AAM in the list
        // verifying the contents
        AAM aam = aams.get(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID);
        // this expected PlatformAAM is due to the value stored in the issued certificate in the test keystore
        assertEquals(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID, aam.getAamInstanceId());
        assertEquals(coreInterfaceAddress, aam.getAamAddress());
        // maybe we could externalize it to spring config
        assertEquals(SecurityConstants.AAM_CORE_AAM_FRIENDLY_NAME, aam.getAamInstanceFriendlyName());
        assertEquals(certificationAuthorityHelper.getAAMCert(), aam.getCertificate().getCertificateString());
    }

    /**
     * Features: Core AAM  providing list of available security entrypoints
     * CommunicationType REST
     */
    @Test
    public void getAvailableAAMsOverRESTWithRegisteredPlatform() throws SecurityException, IOException,
            TimeoutException {
        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        ResponseEntity<Map<String, AAM>> response = restTemplate.exchange(serverAddress + SecurityConstants
                .AAM_GET_AVAILABLE_AAMS, HttpMethod.GET, null, new ParameterizedTypeReference<Map<String, AAM>>() {
        });
        assertEquals(HttpStatus.OK, response.getStatusCode());

        // verify the body
        Map<String, AAM> aams = response.getBody();

        // there should be only core AAM in the list
        assertEquals(2, aams.size());

        // verifying the contents
        // first should be served the core AAM
        AAM coreAAM = (AAM) aams.values().toArray()[0];
        // this expected PlatformAAM is due to the value stored in the issued certificate in the test keystore
        assertEquals(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID, coreAAM.getAamInstanceId());
        assertEquals(coreInterfaceAddress, coreAAM.getAamAddress());
        assertEquals(SecurityConstants.AAM_CORE_AAM_FRIENDLY_NAME, coreAAM.getAamInstanceFriendlyName());

        // then comes the registered platform
        AAM platformAAM = (AAM) aams.values().toArray()[1];
        assertEquals(preferredPlatformId, platformAAM.getAamInstanceId());
        assertEquals(platformInterworkingInterfaceAddress + platformAAMSuffixAtInterWorkingInterface, platformAAM
                .getAamAddress());
        assertEquals(platformInstanceFriendlyName, platformAAM.getAamInstanceFriendlyName());
        // TODO we don't know the cert... until R3 when we will know it
        assertEquals("", platformAAM.getCertificate().getCertificateString());

    }
}