package eu.h2020.symbiote.security.functional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import com.fasterxml.jackson.core.type.TypeReference;

import eu.h2020.symbiote.security.AbstractAAMAMQPTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.OwnedService;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.listeners.amqp.consumers.FederationManagementRequestConsumer;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.User;

/**
 * Test suite for Core AAM deployment scenarios.
 */
@TestPropertySource("/core.properties")
public class OtherListenersFunctionalTests extends
        AbstractAAMAMQPTestSuite {

    @Value("${rabbit.queue.ownedservices.request}")
    protected String ownedServicesRequestQueue;

    private User platformOwner;
    private User smartSpaceOwner;

    @Autowired
    private RabbitTemplate rabbitTemplate;
    @Autowired
    private ComponentCertificatesRepository componentCertificatesRepository;
    @Autowired
    private ApplicationContext ctx;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        //registration of the users used in tests
        platformOwner = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.NEW);
        smartSpaceOwner = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.NEW);
        userRepository.save(platformOwner);
        userRepository.save(smartSpaceOwner);
    }

    /**
     * Features: Core AAM  providing list of available security entrypoints
     * CommunicationType REST
     */
    @Test
    public void getAvailableAAMsOverRESTSuccess() throws SecurityException, IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException {

        // issue platform registration
        Platform platform = new Platform(platformId, platformInterworkingInterfaceAddress, platformInstanceFriendlyName, platformOwner, new Certificate(), new HashMap<>());
        // inject platform AAM Cert
        Certificate platformAAMCertificate = new Certificate(CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1")));
        platform.setPlatformAAMCertificate(platformAAMCertificate);
        // save the service into the repo
        platformRepository.save(platform);

        // issue smartSpace registration
        SmartSpace smartSpace = new SmartSpace(preferredSmartSpaceId, smartSpaceInstanceFriendlyName, smartSpaceGateWayAddress, isExposingSiteLocalAddress, smartSpaceSiteLocalAddress, new Certificate(), new HashMap<>(), smartSpaceOwner);
        // inject platform AAM Cert
        Certificate smartSpaceAAMCertificate = new Certificate(CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1")));
        smartSpace.setLocalCertificationAuthorityCertificate(smartSpaceAAMCertificate);
        // save the service into the repo
        smartSpaceRepository.save(smartSpace);


        AvailableAAMsCollection response = aamClient.getAvailableAAMs();
        // verify the body
        Map<String, AAM> aams = response.getAvailableAAMs();
        // there should be core, one platform and one smart Space AAM in the list
        assertEquals(3, aams.size());
        // verifying the contents
        //expect CoreAAM
        AAM coreAAM = aams.get(SecurityConstants.CORE_AAM_INSTANCE_ID);
        assertEquals(SecurityConstants.CORE_AAM_INSTANCE_ID, coreAAM.getAamInstanceId());
        assertEquals(coreInterfaceAddress + SecurityConstants.AAM_PATH_PREFIX, coreAAM.getAamAddress());
        assertEquals(SecurityConstants.CORE_AAM_FRIENDLY_NAME, coreAAM.getAamInstanceFriendlyName());
        // then comes the registered platform
        assertTrue(aams.containsKey(platformId));
        AAM platformAAM = aams.get(platformId);
        assertEquals(platformId, platformAAM.getAamInstanceId());
        assertEquals(platformInterworkingInterfaceAddress + SecurityConstants.AAM_PATH_PREFIX, platformAAM
                .getAamAddress());
        assertEquals(platformInstanceFriendlyName, platformAAM.getAamInstanceFriendlyName());
        assertEquals(platformAAMCertificate.getCertificateString(), platformAAM.getAamCACertificate().getCertificateString());
        assertEquals(0, platformAAM.getComponentCertificates().size());
        // and then comes the registered smartSpace
        assertTrue(aams.containsKey(preferredSmartSpaceId));
        AAM smartSpaceAAM = aams.get(preferredSmartSpaceId);
        assertEquals(preferredSmartSpaceId, smartSpaceAAM.getAamInstanceId());
        assertEquals(smartSpaceSiteLocalAddress + SecurityConstants.AAM_PATH_PREFIX, smartSpaceAAM.getSiteLocalAddress());
        assertEquals(smartSpaceGateWayAddress + SecurityConstants.AAM_PATH_PREFIX, smartSpaceAAM.getAamAddress());
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
    public void getPlatformCertificateOverRESTSuccess() throws
            IOException,
            AAMException {
        String componentCertificate = aamClient.getComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME, SecurityConstants.CORE_AAM_INSTANCE_ID);
        assertEquals(certificationAuthorityHelper.getAAMCert(), componentCertificate);
    }

    @Test
    public void getLocalComponentCertificateOverRESTSuccess() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            AAMException {
        //component adding
        ComponentCertificate componentCert = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "keystores/core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(componentCert);
        String componentCertificate = aamClient.getComponentCertificate(componentId, SecurityConstants.CORE_AAM_INSTANCE_ID);
        assertEquals(componentCert.getCertificate().getCertificateString(), componentCertificate);
    }

    @Test(expected = AAMException.class)
    public void getLocalComponentCertificateOverRESTNotRegisteredComponent() throws
            AAMException {
        aamClient.getComponentCertificate("wrong", SecurityConstants.CORE_AAM_INSTANCE_ID);

    }

    @Test
    public void getOwnedServicesForServiceOwnerInAdministrationSuccess() throws
            IOException,
            InvalidArgumentsException {

        // verify that our services is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.existsById(platformId));
        assertTrue(userRepository.existsById(platformOwnerUsername));

        User serviceOwner = userRepository.findById(platformOwnerUsername).get();
        // service owner should have no services bound to him by now
        assertTrue(serviceOwner.getOwnedServices().isEmpty());

        // creating request
        UserManagementRequest userManagementRequest = new UserManagementRequest();
        userManagementRequest.setAdministratorCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        userManagementRequest.setUserCredentials(new Credentials(platformOwnerUsername, ""));

        // issue owned services request

        byte[] response = rabbitTemplate.sendAndReceive(ownedServicesRequestQueue, new Message(mapper.writeValueAsBytes(userManagementRequest), new MessageProperties())).getBody();
        Set<OwnedService> responseSet = mapper.readValue(response, new TypeReference<Set<OwnedService>>() {
        });
        // no services there yet
        assertTrue(responseSet.isEmpty());

        // register smart space and platform in repositories
        Platform platform = new Platform(platformId,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                serviceOwner,
                new Certificate(),
                new HashMap<>());
        platformRepository.save(platform);
        serviceOwner.getOwnedServices().add(platformId);
        userRepository.save(serviceOwner);
        SmartSpace smartSpace = new SmartSpace(preferredSmartSpaceId,
                smartSpaceInstanceFriendlyName,
                smartSpaceGateWayAddress,
                isExposingSiteLocalAddress,
                smartSpaceSiteLocalAddress,
                new Certificate(),
                new HashMap<>(),
                serviceOwner);
        smartSpaceRepository.save(smartSpace);
        serviceOwner.getOwnedServices().add(preferredSmartSpaceId);
        userRepository.save(serviceOwner);


        // issue owned services request
        response = rabbitTemplate.sendAndReceive(ownedServicesRequestQueue, new Message(mapper.writeValueAsBytes
                (userManagementRequest), new MessageProperties())).getBody();

        responseSet = mapper.readValue(response, new TypeReference<Set<OwnedService>>() {
        });

        // there should be a platform and a smart space
        assertEquals(2, responseSet.size());

        for (OwnedService ownedService : responseSet) {
            if (ownedService.getServiceType().equals(OwnedService.ServiceType.PLATFORM)) {
                assertEquals(platformId, ownedService.getServiceInstanceId());
                assertEquals(platformInstanceFriendlyName, ownedService.getInstanceFriendlyName());
                assertEquals(platformInterworkingInterfaceAddress, ownedService.getPlatformInterworkingInterfaceAddress());
                assertTrue(ownedService.getExternalAddress().isEmpty());
                assertTrue(ownedService.getSiteLocalAddress().isEmpty());
            } else {
                assertEquals(preferredSmartSpaceId, ownedService.getServiceInstanceId());
                assertEquals(smartSpaceInstanceFriendlyName, ownedService.getInstanceFriendlyName());
                assertEquals(smartSpaceGateWayAddress, ownedService.getExternalAddress());
                assertEquals(isExposingSiteLocalAddress, ownedService.isExposingSiteLocalAddress());
                assertEquals(smartSpaceSiteLocalAddress, ownedService.getSiteLocalAddress());
                assertTrue(ownedService.getPlatformInterworkingInterfaceAddress().isEmpty());
            }
        }
    }


    @Test
    public void getOwnedServicesForServiceOwnerInAdministrationFailUnauthorized()
            throws
            IOException {

        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.existsById(platformId));
        assertTrue(userRepository.existsById(platformOwnerUsername));
        // put platform into db
        Platform platform = new Platform(platformId,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                platformOwner,
                new Certificate(),
                new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedServices().add(platformId);
        userRepository.save(platformOwner);

        User platformOwner = userRepository.findById(platformOwnerUsername).get();
        // platform owner should have a platform bound to him by now
        assertFalse(platformOwner.getOwnedServices().isEmpty());
        // creating request
        UserManagementRequest userManagementRequest = new UserManagementRequest();
        userManagementRequest.setAdministratorCredentials(new Credentials(AAMOwnerUsername, "bad_password"));
        userManagementRequest.setUserCredentials(new Credentials(platformOwnerUsername, ""));

        // issue owned platform details request with the given token
        byte[] response = rabbitTemplate.sendAndReceive(ownedServicesRequestQueue, new Message(mapper.writeValueAsBytes
                (userManagementRequest), new MessageProperties())).getBody();

        try {
            mapper.readValue(response, new TypeReference<Set<OwnedService>>() {
            });
            assert false;
        } catch (Exception e) {
            ErrorResponseContainer error = mapper.readValue(response, ErrorResponseContainer.class);
            assertEquals(HttpStatus.UNAUTHORIZED.value(), error.getErrorCode());
        }
    }

    @Test
    public void sendMessageOverAMQPFailWrongMessage() throws
            IOException {
        String wrongmessage = "{wrong message json}";
        // send incorrect message over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(ownedServicesRequestQueue, new Message(mapper.writeValueAsBytes
                (wrongmessage), new MessageProperties())).getBody();
        ErrorResponseContainer sspRegistrationOverAMQPResponse = mapper.readValue(response,
                ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), sspRegistrationOverAMQPResponse.getErrorCode());
    }

    @Test
    public void checkAvailabilityOfFederationManagementAMQPListener() {
        char c[] = FederationManagementRequestConsumer.class.getSimpleName().toCharArray();
        c[0] = Character.toLowerCase(c[0]);
        String beanName = new String(c);
        assertFalse(ctx.containsBean(beanName));
    }

}
