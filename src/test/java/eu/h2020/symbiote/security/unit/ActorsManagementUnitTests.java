package eu.h2020.symbiote.security.unit;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.RegistrationStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.interfaces.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.interfaces.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.listeners.rest.AAMServices;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAMConnectionProblem;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.TestPropertySource;

import java.security.cert.CertificateException;
import java.util.*;

import static org.junit.Assert.*;


@TestPropertySource("/core.properties")
public class ActorsManagementUnitTests extends AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(ClientCertificatesIssuingUnitTests.class);
    protected final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    private final String recoveryMail = "null@dev.null";
    private final String federatedOAuthId = "federatedOAuthId";
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
    @Autowired
    private ValidationHelper validationHelper;
    @Autowired
    private TokenIssuer tokenIssuer;
    @Autowired
    private GetTokenService getTokenService;
    @Autowired
    private RevocationHelper revocationHelper;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    private AAMServices coreServicesController;

    @Bean
    DummyPlatformAAM getDummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

    @Bean
    DummyPlatformAAMConnectionProblem getDummyPlatformAAMConnectionProblem() {
        return new DummyPlatformAAMConnectionProblem();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // platform registration useful
        platformRegistrationOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformRegistrationRequestQueue, 5000);
        platformOwnerUserCredentials = new Credentials(platformOwnerUsername, platformOwnerPassword);
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId);
    }

    @Test
    public void userInternalRegistrationSuccess() throws SecurityException {
        String appUsername = "NewApplication";

        // verify that app is not in the repository
        User registeredUser = userRepository.findOne(appUsername);
        assertNull(registeredUser);

            /*
             XXX federated Id and recovery mail are required for Test & Core AAM but not for Platform AAM
             */
        // register new user to db
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials
                (appUsername, "NewPassword"), "nullId", "nullMail", UserRole.USER));
        RegistrationStatus userRegistrationResponse = usersManagementService.register
                (userManagementRequest);

        // verify that app really is in repository
        registeredUser = userRepository.findOne(appUsername);
        assertNotNull(registeredUser);
        assertEquals(UserRole.USER, registeredUser.getRole());

        assertEquals(userRegistrationResponse, RegistrationStatus.OK);

        // TODO verify that released certificate has no CA property
        //assertFalse(registeredUser.getClientCertificate().getX509().getExtensionValue(new ASN1ObjectIdentifier
        // ("2.5.29.19"),));
    }

    @Test
    public void userInternalUnregistrationSuccess() throws SecurityException, CertificateException {

        // prepare the user in db
        userRepository.save(new User(username, passwordEncoder.encode(password), recoveryMail, new HashMap<>(), UserRole.USER, new ArrayList<>()));

        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // unregister the user
        usersManagementService.unregister(username);
        log.debug("User successfully unregistered!");

        // verify that app is not anymore in the repository
        assertFalse(userRepository.exists(username));

        // verify that the user certificate was indeed revoked
        assertTrue(revokedKeysRepository.exists(username));
        SubjectsRevokedKeys revokedKeys = revokedKeysRepository.findOne(username);
        assertNotNull(revokedKeys);

        Set<String> certs = new HashSet<String>();
        for (Certificate c : user.getClientCertificates().values()) {
            certs.add(Base64.getEncoder().encodeToString(c.getX509().getPublicKey().getEncoded()));
        }

        assertTrue(revokedKeys.getRevokedKeysSet().containsAll(certs));
    }

}