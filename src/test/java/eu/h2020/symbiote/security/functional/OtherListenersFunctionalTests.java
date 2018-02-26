package eu.h2020.symbiote.security.functional;

import com.fasterxml.jackson.core.type.TypeReference;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.junit.Before;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * Test suite for Core AAM deployment scenarios.
 */
@TestPropertySource("/core.properties")
public class OtherListenersFunctionalTests extends
        AbstractAAMTestSuite {

    private final String recoveryMail = "null@dev.null";
    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";

    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    String coreInterfaceAddress;
    @Value("${rabbit.queue.get.platform.owners.names}")
    private String getPlatformOwnersNamesQueue;
    @Value("${rabbit.routingKey.get.platform.owners.names}")
    private String getPlatformOwnersNamesRoutingKey;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    private User platformOwner;
    private User smartSpaceOwner;

    @Autowired
    private RabbitTemplate rabbitTemplate;
    @Autowired
    private ComponentCertificatesRepository componentCertificatesRepository;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        //user registration useful
        platformOwner = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        smartSpaceOwner = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(platformOwner);
        // platform registration useful
        platformOwnerUserCredentials = new Credentials(platformOwner.getUsername(), platformOwner.getPasswordEncrypted());
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId, OperationType.CREATE);
    }

    /**
     * Features: Core AAM  providing list of available security entry points
     * CommunicationType REST
     */

    @Test
    public void getAvailableAAMsOverRESTWithNoRegisteredPlatforms() throws NoSuchAlgorithmException,
            CertificateException, NoSuchProviderException, KeyStoreException, IOException, AAMException {

        // injecting core component certificate
        String componentId = "registry";
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);

        AvailableAAMsCollection response = aamClient.getAvailableAAMs();
        // verify the body
        Map<String, AAM> aams = response.getAvailableAAMs();
        // there should be only core AAM in the list
        // verifying the contents
        AAM aam = aams.get(SecurityConstants.CORE_AAM_INSTANCE_ID);
        // this expected PlatformAAM is due to the value stored in the issued certificate in the test keystore
        assertEquals(SecurityConstants.CORE_AAM_INSTANCE_ID, aam.getAamInstanceId());
        assertEquals(coreInterfaceAddress, aam.getAamAddress());
        // maybe we could externalize it to spring config
        assertEquals(SecurityConstants.CORE_AAM_FRIENDLY_NAME, aam.getAamInstanceFriendlyName());
        assertEquals(certificationAuthorityHelper.getAAMCert(), aam.getAamCACertificate().getCertificateString());

        // should contain one component certificate
        assertEquals(1, aam.getComponentCertificates().size());
        assertEquals(componentCertificate.getCertificate().getCertificateString(), aam.getComponentCertificates().get(componentId).getCertificateString());
    }

    /**
     * Features: Core AAM  providing list of available security entrypoints
     * CommunicationType REST
     */
    @Test
    public void getAvailableAAMsOverRESTWithRegisteredServices() throws SecurityException, IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException {

        // issue platform registration
        Platform platform = new Platform(preferredPlatformId, platformInterworkingInterfaceAddress, platformInstanceFriendlyName, platformOwner, new Certificate(), new HashMap<>());
        // inject platform AAM Cert
        Certificate platformAAMCertificate = new Certificate(CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1")));
        platform.setPlatformAAMCertificate(platformAAMCertificate);
        // save the certs into the repo
        platformRepository.save(platform);

        // issue smartSpace registration
        SmartSpace smartSpace = new SmartSpace(preferredSmartSpaceId, smartSpaceGateWayAddress, smartSpaceSiteLocalAddress, exposedIIAddress, smartSpaceInstanceFriendlyName, new Certificate(), new HashMap<>(), smartSpaceOwner);
        // inject platform AAM Cert
        Certificate smartSpaceAAMCertificate = new Certificate(CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1")));
        smartSpace.setAamCertificate(smartSpaceAAMCertificate);
        // save the certs into the repo
        smartSpaceRepository.save(smartSpace);


        AvailableAAMsCollection response = aamClient.getAvailableAAMs();
        // verify the body
        Map<String, AAM> aams = response.getAvailableAAMs();
        // there should be only core AAM in the list
        assertEquals(3, aams.size());
        // verifying the contents
        AAM coreAAM = aams.get(SecurityConstants.CORE_AAM_INSTANCE_ID);
        // this expected PlatformAAM is due to the value stored in the issued certificate in the test keystore
        assertEquals(SecurityConstants.CORE_AAM_INSTANCE_ID, coreAAM.getAamInstanceId());
        assertEquals(coreInterfaceAddress, coreAAM.getAamAddress());
        assertEquals(SecurityConstants.CORE_AAM_FRIENDLY_NAME, coreAAM.getAamInstanceFriendlyName());
        // then comes the registered platform
        assertTrue(aams.containsKey(preferredPlatformId));
        AAM platformAAM = aams.get(preferredPlatformId);
        assertEquals(preferredPlatformId, platformAAM.getAamInstanceId());
        assertEquals(platformInterworkingInterfaceAddress + platformAAMSuffixAtInterWorkingInterface, platformAAM
                .getAamAddress());
        assertEquals(platformInstanceFriendlyName, platformAAM.getAamInstanceFriendlyName());
        assertEquals(platformAAMCertificate.getCertificateString(), platformAAM.getAamCACertificate().getCertificateString());
        assertEquals(0, platformAAM.getComponentCertificates().size());
        // and then comes the registered smartSpace
        assertTrue(aams.containsKey(preferredSmartSpaceId));
        AAM smartSpaceAAM = aams.get(preferredSmartSpaceId);
        assertEquals(preferredSmartSpaceId, smartSpaceAAM.getAamInstanceId());
        assertEquals(smartSpaceSiteLocalAddress, smartSpaceAAM.getSiteLocalAddress());
        assertEquals(smartSpaceGateWayAddress, smartSpaceAAM.getAamAddress());


        assertEquals(smartSpaceInstanceFriendlyName, smartSpaceAAM.getAamInstanceFriendlyName());
        assertEquals(smartSpaceAAMCertificate.getCertificateString(), smartSpaceAAM.getAamCACertificate().getCertificateString());
        assertEquals(0, smartSpaceAAM.getComponentCertificates().size());

    }

    /**
     * Features: CAAM - 12 (AAM as a CA)
     * Interfaces: CAAM - 15;
     * CommunicationType REST
     */
    @Test
    public void getLocalComponentCertificateOverRESTSuccess() throws NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException, KeyStoreException, IOException, AAMException {
        String componentCertificate = aamClient.getComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME, SecurityConstants.CORE_AAM_INSTANCE_ID);
        assertEquals(certificationAuthorityHelper.getAAMCert(), componentCertificate);
    }

    @Test(expected = AAMException.class)
    public void getLocalComponentCertificateOverRESTWrongComponentIdentifier() throws
            AAMException {
        aamClient.getComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME+"wrong", SecurityConstants.CORE_AAM_INSTANCE_ID);

    }

    @Test
    public void getOwnedPlatformDetailsForPlatformOwnerInAdministrationSuccess() throws IOException {

        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        User platformOwner = userRepository.findOne(platformOwnerUsername);
        // platform owner should have no platform bound to him by now
        assertTrue(platformOwner.getOwnedServices().isEmpty());

        // creating request
        UserManagementRequest userManagementRequest = new UserManagementRequest();
        userManagementRequest.setAdministratorCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        userManagementRequest.setUserCredentials(new Credentials(platformOwnerUsername, ""));

        // issue owned platform details request

        byte[] response = rabbitTemplate.sendAndReceive(ownedPlatformDetailsRequestQueue, new Message(mapper.writeValueAsBytes(userManagementRequest), new MessageProperties())).getBody();
        Set<OwnedPlatformDetails> responseSet = mapper.readValue(response, new TypeReference<Set<OwnedPlatformDetails>>() {
        });
        // no platforms there yet
        assertTrue(responseSet.isEmpty());

        // issue platform registration over AMQP
        response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformManagementResponse = mapper.readValue(response, PlatformManagementResponse.class);
        assertEquals(ManagementStatus.OK, platformManagementResponse.getRegistrationStatus());
        platformOwner = userRepository.findOne(platformOwnerUsername);
        // platform owner should have a platform bound to him by now
        assertFalse(platformOwner.getOwnedServices().isEmpty());

        // issue owned platform details request
        response = rabbitTemplate.sendAndReceive(ownedPlatformDetailsRequestQueue, new Message(mapper.writeValueAsBytes
                (userManagementRequest), new MessageProperties())).getBody();

        responseSet = mapper.readValue(response, new TypeReference<Set<OwnedPlatformDetails>>() {
        });

        // there should be a platform
        assertFalse(responseSet.isEmpty());

        OwnedPlatformDetails platformDetailsFromResponse = responseSet.iterator().next();
        Platform ownedPlatformInDB = platformRepository.findOne(preferredPlatformId);

        // verify the contents of the response
        assertEquals(ownedPlatformInDB.getPlatformInstanceFriendlyName(), platformDetailsFromResponse
                .getPlatformInstanceFriendlyName());
        assertEquals(ownedPlatformInDB.getPlatformInstanceId(), platformDetailsFromResponse.getPlatformInstanceId());
        assertEquals(ownedPlatformInDB.getPlatformInterworkingInterfaceAddress(), platformDetailsFromResponse
                .getPlatformInterworkingInterfaceAddress());


        // issue second platform registration over AMQP
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress + "/second",
                platformInstanceFriendlyName,
                platformId + "2",
                OperationType.CREATE);
        // issue platform registration over AMQP
        response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        platformManagementResponse = mapper.readValue(response, PlatformManagementResponse.class);
        assertEquals(ManagementStatus.OK, platformManagementResponse.getRegistrationStatus());

        platformOwner = userRepository.findOne(platformOwnerUsername);
        // platform owner should have a platform bound to him by now
        assertFalse(platformOwner.getOwnedServices().isEmpty());

        // issue owned platform details request
        response = rabbitTemplate.sendAndReceive(ownedPlatformDetailsRequestQueue, new Message(mapper.writeValueAsBytes
                (userManagementRequest), new MessageProperties())).getBody();

        responseSet = mapper.readValue(response, new TypeReference<Set<OwnedPlatformDetails>>() {
        });
        assertEquals(2, responseSet.size());
    }


    @Test
    public void getOwnedPlatformDetailsForPlatformOwnerInAdministrationUnauthorized()
            throws
            IOException {

        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformManagementResponse = mapper.readValue(response, PlatformManagementResponse.class);
        assertEquals(ManagementStatus.OK, platformManagementResponse.getRegistrationStatus());

        User platformOwner = userRepository.findOne(platformOwnerUsername);
        // platform owner should have a platform bound to him by now
        assertFalse(platformOwner.getOwnedServices().isEmpty());
        // creating request
        UserManagementRequest userManagementRequest = new UserManagementRequest();
        userManagementRequest.setAdministratorCredentials(new Credentials(AAMOwnerUsername, "bad_password"));
        userManagementRequest.setUserCredentials(new Credentials(platformOwnerUsername, ""));

        // issue owned platform details request with the given token
        response = rabbitTemplate.sendAndReceive(ownedPlatformDetailsRequestQueue, new Message(mapper.writeValueAsBytes
                (userManagementRequest), new MessageProperties())).getBody();

        try {
            mapper.readValue(response, new TypeReference<Set<OwnedPlatformDetails>>() {
            });
            assert false;
        } catch (Exception e) {
            ErrorResponseContainer error = mapper.readValue(response, ErrorResponseContainer.class);
            assertEquals(HttpStatus.UNAUTHORIZED.value(), error.getErrorCode());
        }
    }

    @Test
    public void getPlatformOwnersNamesSuccess() throws IOException {
        saveTwoDifferentUsers();
        Set<String> requested = new HashSet<>();
        requested.add(platformId + "One");
        requested.add(platformId + "Two");
        byte[] response = rabbitTemplate.sendAndReceive(getPlatformOwnersNamesQueue, new Message(mapper.writeValueAsBytes(new
                GetPlatformOwnersRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword), requested)), new MessageProperties())).getBody();

        GetPlatformOwnersResponse platformOwners = mapper.readValue(response,
                GetPlatformOwnersResponse.class);
        assertEquals(200, platformOwners.getHttpStatus().value());
        assertNotNull(platformOwners.getplatformsOwners());
        assertEquals("userOne", platformOwners.getplatformsOwners().get(platformId + "One"));
        assertEquals("userTwo", platformOwners.getplatformsOwners().get(platformId + "Two"));
    }

    @Test
    public void getPlatformOwnersNamesFailsForIncorrectAdminCredentials() throws
            IOException {
        saveTwoDifferentUsers();
        Set<String> requested = new HashSet<>();
        requested.add(platformId + "One");
        requested.add(platformId + "Two");
        byte[] response = rabbitTemplate.sendAndReceive(getPlatformOwnersNamesQueue, new Message(mapper.writeValueAsBytes(new
                GetPlatformOwnersRequest(new Credentials(AAMOwnerUsername, wrongPassword), requested)), new MessageProperties())).getBody();
        GetPlatformOwnersResponse platformOwners = mapper.readValue(response,
                GetPlatformOwnersResponse.class);
        assertEquals(401, platformOwners.getHttpStatus().value());
    }

    @Test
    public void getPlatformOwnersNamesFailsWithoutAdminCredentials() throws
            IOException {
        saveTwoDifferentUsers();
        Set<String> requested = new HashSet<>();
        requested.add(platformId + "One");
        requested.add(platformId + "Two");
        byte[] response = rabbitTemplate.sendAndReceive(getPlatformOwnersNamesQueue, new Message(mapper.writeValueAsBytes(new
                GetPlatformOwnersRequest(null, requested)), new MessageProperties())).getBody();
        GetPlatformOwnersResponse platformOwners = mapper.readValue(response,
                GetPlatformOwnersResponse.class);
        assertEquals(401, platformOwners.getHttpStatus().value());
    }
}
