package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
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
public class OtherListenersFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(OtherListenersFunctionalTests.class);
    private final String recoveryMail = "null@dev.null";
    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
    private final String platformOwnerUsername = "testPlatformOwnerUsername";
    private final String platformOwnerPassword = "testPlatormOwnerPassword";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;

    @Bean
    DummyPlatformAAM dummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

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
    }

    /**
     * Features: Core AAM  providing list of available security entry points
     * CommunicationType REST
     */

    @Test
    public void getAvailableAAMsOverRESTWithNoRegisteredPlatforms() throws NoSuchAlgorithmException,
            CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        AvailableAAMsCollection response = restaamClient.getAvailableAAMs();
        // verify the body
        Map<String, AAM> aams = response.getAvailableAAMs();
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
        AvailableAAMsCollection response = restaamClient.getAvailableAAMs();
        // verify the body
        Map<String, AAM> aams = response.getAvailableAAMs();
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

    /**
     * Features: CAAM - 12 (AAM as a CA)
     * Interfaces: CAAM - 15;
     * CommunicationType REST
     */
    @Test
    public void getComponentCertificateOverRESTSuccess() throws NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException, KeyStoreException, IOException {
        try {
            String componentCertificate = restaamClient.getComponentCertificate();
            assertEquals(certificationAuthorityHelper.getAAMCert(), componentCertificate);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
    }
}