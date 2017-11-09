package eu.h2020.symbiote.security.functional;

import com.fasterxml.jackson.core.type.TypeReference;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.codehaus.jettison.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for Core AAM deployment scenarios.
 */
@TestPropertySource("/core.properties")
public class OtherListenersFunctionalTests extends
        AbstractAAMTestSuite {

    private final Log log = LogFactory.getLog(OtherListenersFunctionalTests.class);
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
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    private RpcClient getPlatformsOwnersClient;

    @Autowired
    private ComponentCertificatesRepository componentCertificatesRepository;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        //user registration useful
        User user = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.PLATFORM_OWNER);
        userRepository.save(user);
        getPlatformsOwnersClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                getPlatformOwnersNamesQueue, 5000);
        // platform registration useful
        platformRegistrationOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformManagementRequestQueue, 5000);
        platformOwnerUserCredentials = new Credentials(user.getUsername(), user.getPasswordEncrypted());
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
    public void getAvailableAAMsOverRESTWithRegisteredPlatform() throws SecurityException, IOException,
            TimeoutException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException {

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // inject platform AAM Cert
        Platform platform = platformRepository.findOne(preferredPlatformId);
        Certificate platformAAMCertificate = new Certificate(CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1")));
        platform.setPlatformAAMCertificate(platformAAMCertificate);

        // save the certs into the repo
        platformRepository.save(platform);

        AvailableAAMsCollection response = aamClient.getAvailableAAMs();
        // verify the body
        Map<String, AAM> aams = response.getAvailableAAMs();
        // there should be only core AAM in the list
        assertEquals(2, aams.size());
        // verifying the contents
        // first should be served the core AAM
        AAM coreAAM = (AAM) aams.values().toArray()[0];
        // this expected PlatformAAM is due to the value stored in the issued certificate in the test keystore
        assertEquals(SecurityConstants.CORE_AAM_INSTANCE_ID, coreAAM.getAamInstanceId());
        assertEquals(coreInterfaceAddress, coreAAM.getAamAddress());
        assertEquals(SecurityConstants.CORE_AAM_FRIENDLY_NAME, coreAAM.getAamInstanceFriendlyName());
        // then comes the registered platform
        AAM platformAAM = (AAM) aams.values().toArray()[1];
        assertEquals(preferredPlatformId, platformAAM.getAamInstanceId());
        assertEquals(platformInterworkingInterfaceAddress + platformAAMSuffixAtInterWorkingInterface, platformAAM
                .getAamAddress());
        assertEquals(platformInstanceFriendlyName, platformAAM.getAamInstanceFriendlyName());
        assertEquals(platformAAMCertificate.getCertificateString(), platformAAM.getAamCACertificate().getCertificateString());
        assertEquals(0, platformAAM.getComponentCertificates().size());
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
    public void getLocalComponentCertificateOverRESTWrongComponentIdentifier() throws NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException, KeyStoreException, IOException, AAMException {
        aamClient.getComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME+"wrong", SecurityConstants.CORE_AAM_INSTANCE_ID);

    }

    @Test
    public void getOwnedPlatformDetailsForPlatformOwnerInAdministrationSuccess() throws IOException, TimeoutException {

        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        User platformOwner = userRepository.findOne(platformOwnerUsername);
        // platform owner should have no platform bound to him by now
        assertTrue(platformOwner.getOwnedPlatforms().isEmpty());

        // creating request
        UserManagementRequest userManagementRequest = new UserManagementRequest();
        userManagementRequest.setAdministratorCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        userManagementRequest.setUserCredentials(new Credentials(platformOwnerUsername, ""));

        // issue owned platform details request
        RpcClient ownedPlatformsDetailsRPCClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = ownedPlatformsDetailsRPCClient.primitiveCall(mapper.writeValueAsString
                (userManagementRequest).getBytes());

        Set<OwnedPlatformDetails> responseSet = mapper.readValue(ownedPlatformRawResponse, new TypeReference<Set<OwnedPlatformDetails>>() {
        });

        // no platforms there yet
        assertTrue(responseSet.isEmpty());

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        platformOwner = userRepository.findOne(platformOwnerUsername);
        // platform owner should have a platform bound to him by now
        assertFalse(platformOwner.getOwnedPlatforms().isEmpty());

        // issue owned platform details request
        ownedPlatformRawResponse = ownedPlatformsDetailsRPCClient.primitiveCall(mapper.writeValueAsString
                (userManagementRequest).getBytes());

        responseSet = mapper.readValue(ownedPlatformRawResponse, new TypeReference<Set<OwnedPlatformDetails>>() {
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
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        platformOwner = userRepository.findOne(platformOwnerUsername);
        // platform owner should have a platform bound to him by now
        assertFalse(platformOwner.getOwnedPlatforms().isEmpty());

        // issue owned platform details request
        ownedPlatformRawResponse = ownedPlatformsDetailsRPCClient.primitiveCall(mapper.writeValueAsString
                (userManagementRequest).getBytes());

        responseSet = mapper.readValue(ownedPlatformRawResponse, new TypeReference<Set<OwnedPlatformDetails>>() {
        });

        assertEquals(2, responseSet.size());


        // issue second platform registration over AMQP
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                platformInterworkingInterfaceAddress + "/third",
                platformInstanceFriendlyName,
                "",
                OperationType.CREATE);
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        platformOwner = userRepository.findOne(platformOwnerUsername);
        // platform owner should have a platform bound to him by now
        assertFalse(platformOwner.getOwnedPlatforms().isEmpty());

        // issue owned platform details request
        ownedPlatformRawResponse = ownedPlatformsDetailsRPCClient.primitiveCall(mapper.writeValueAsString
                (userManagementRequest).getBytes());

        responseSet = mapper.readValue(ownedPlatformRawResponse, new TypeReference<Set<OwnedPlatformDetails>>() {
        });

        assertEquals(3, responseSet.size());
    }


    @Test
    public void getOwnedPlatformDetailsForPlatformOwnerInAdministrationUnauthorized()
            throws
            IOException,
            TimeoutException,
            MalformedJWTException,
            JSONException,
            CertificateException,
            ValidationException,
            InterruptedException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            OperatorCreationException,
            UnrecoverableKeyException,
            InvalidKeyException,
            JWTCreationException, WrongCredentialsException {

        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        User platformOwner = userRepository.findOne(platformOwnerUsername);
        // platform owner should have a platform bound to him by now
        assertFalse(platformOwner.getOwnedPlatforms().isEmpty());
        // creating request
        UserManagementRequest userManagementRequest = new UserManagementRequest();
        userManagementRequest.setAdministratorCredentials(new Credentials(AAMOwnerUsername, "bad_password"));
        userManagementRequest.setUserCredentials(new Credentials(platformOwnerUsername, ""));

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (userManagementRequest).getBytes());

        try {
            mapper.readValue(ownedPlatformRawResponse, new TypeReference<Set<OwnedPlatformDetails>>() {
            });
            assert false;
        } catch (Exception e) {
            ErrorResponseContainer error = mapper.readValue(ownedPlatformRawResponse, ErrorResponseContainer.class);
            assertEquals(HttpStatus.UNAUTHORIZED.value(), error.getErrorCode());
        }
    }

    private X509Certificate getCertificateFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
    }

    @Test
    public void getPlatformOwnersNamesSuccess() throws IOException, TimeoutException, CertificateException {
        saveTwoDifferentUsers();
        Set<String> requested = new HashSet<>();
        requested.add(platformId + "One");
        requested.add(platformId + "Two");
        byte[] response = getPlatformsOwnersClient.primitiveCall(mapper.writeValueAsString(new
                GetPlatformOwnersRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword), requested)).getBytes());

        GetPlatformOwnersResponse platformOwners = mapper.readValue(response,
                GetPlatformOwnersResponse.class);
        assertEquals(platformOwners.getHttpStatus().value(), 200);
        assertNotNull(platformOwners.getplatformsOwners());
        assertEquals("userOne", platformOwners.getplatformsOwners().get(platformId + "One"));
        assertEquals("userTwo", platformOwners.getplatformsOwners().get(platformId + "Two"));
    }

    @Test
    public void getPlatformOwnersNamesFailsForIncorrectAdminCredentials() throws
            IOException,
            TimeoutException,
            CertificateException {
        saveTwoDifferentUsers();
        Set<String> requested = new HashSet<>();
        requested.add(platformId + "One");
        requested.add(platformId + "Two");
        byte[] response = getPlatformsOwnersClient.primitiveCall(mapper.writeValueAsString(new
                GetPlatformOwnersRequest(new Credentials(AAMOwnerUsername, wrongPassword), requested)).getBytes());

        GetPlatformOwnersResponse platformOwners = mapper.readValue(response,
                GetPlatformOwnersResponse.class);
        assertEquals(401, platformOwners.getHttpStatus().value());
    }

    @Test
    public void getPlatformOwnersNamesFailsWithoutAdminCredentials() throws
            IOException,
            TimeoutException,
            CertificateException {
        saveTwoDifferentUsers();
        Set<String> requested = new HashSet<>();
        requested.add(platformId + "One");
        requested.add(platformId + "Two");
        byte[] response = getPlatformsOwnersClient.primitiveCall(mapper.writeValueAsString(new
                GetPlatformOwnersRequest(null, requested)).getBytes());

        GetPlatformOwnersResponse platformOwners = mapper.readValue(response,
                GetPlatformOwnersResponse.class);
        assertEquals(401, platformOwners.getHttpStatus().value());
    }
}
