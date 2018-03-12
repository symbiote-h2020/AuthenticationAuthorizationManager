package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ServiceManagementException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.PlatformsManagementService;
import eu.h2020.symbiote.security.services.SmartSpacesManagementService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class PlatformManagementUnitTests extends
        AbstractAAMTestSuite {

    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
    private final String platformId = "testPlatformId";
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    String coreInterfaceAddress;
    @Autowired
    PlatformsManagementService platformsManagementService;
    @Autowired
    SmartSpacesManagementService smartSpacesManagementService;
    private Credentials platformOwnerCredentials;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        // db cleanup
        platformRepository.deleteAll();
        smartSpaceRepository.deleteAll();
        userRepository.deleteAll();

        //user registration useful
        User user = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(user);
        platformOwnerCredentials = new Credentials(platformOwnerUsername, platformOwnerPassword);
    }

    @Test
    public void platformRegistrationWithPreferredPlatformIdSuccess() throws
            SecurityException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        User platformOwner = userRepository.findOne(platformOwnerUsername);
        assertTrue(platformOwner.getOwnedServices().isEmpty());

        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);
        // issue platform registration
        PlatformManagementResponse platformRegistrationResponse = platformsManagementService.authManage(platformManagementRequest);

        // verified that we received the preferred platformId
        assertEquals(preferredPlatformId, platformRegistrationResponse.getPlatformId());

        // verify that Service Owner is in repository (as Service Owner!)
        User platformOwnerFromRepository = userRepository.findOne(platformOwnerUsername);
        assertNotNull(platformOwnerFromRepository);
        assertEquals(UserRole.SERVICE_OWNER, platformOwnerFromRepository.getRole());

        // verify that platform with preferred id is in repository and is tied with the given Service Owner
        Platform registeredPlatform = platformRepository.findOne(preferredPlatformId);
        assertNotNull(registeredPlatform);
        // verify that platform oriented fields are properly stored
        assertEquals(platformInterworkingInterfaceAddress, registeredPlatform.getPlatformInterworkingInterfaceAddress());

        // verify that ervice Owner has this platform in his collection
        User platformOwnerFromPlatformEntity = registeredPlatform.getPlatformOwner();
        assertEquals(platformOwnerUsername, platformOwnerFromPlatformEntity.getUsername());
        assertTrue(platformOwnerFromPlatformEntity.getOwnedServices().contains(preferredPlatformId));

        // verify that Service Owner was properly updated in repository with new platform ownership
        assertEquals(platformOwnerUsername, platformOwnerFromRepository.getUsername());
        assertFalse(platformOwnerFromRepository.getOwnedServices().isEmpty());
        assertTrue(platformOwnerFromRepository.getOwnedServices().contains(preferredPlatformId));

        assertEquals(ManagementStatus.OK, platformRegistrationResponse.getRegistrationStatus());
    }

    @Test
    public void platformRegistrationWithGeneratedPlatformIdSuccess() throws
            SecurityException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration without preferred platform identifier
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                "",
                OperationType.CREATE);
        // issue platform registration
        PlatformManagementResponse platformRegistrationResponse = platformsManagementService.authManage(platformManagementRequest);

        // verified that we received a generated platformId
        String generatedPlatformId = platformRegistrationResponse.getPlatformId();
        assertFalse(generatedPlatformId.isEmpty());
        assertTrue(generatedPlatformId.startsWith("PLATFORM_"));

        // verify that Service Owner is in repository (as Service Owner!)
        User registeredPlatformOwner = userRepository.findOne(platformOwnerUsername);
        assertNotNull(registeredPlatformOwner);
        assertEquals(UserRole.SERVICE_OWNER, registeredPlatformOwner.getRole());
        assertTrue(registeredPlatformOwner.getOwnedServices().contains(generatedPlatformId));

        // verify that platform with the generated id is in repository and is tied with the given Service Owner
        Platform registeredPlatform = platformRepository.findOne(generatedPlatformId);
        assertNotNull(registeredPlatform);
        assertEquals(platformOwnerUsername, registeredPlatform.getPlatformOwner().getUsername());

        // verify that platform oriented fields are properly stored
        assertEquals(platformInterworkingInterfaceAddress, registeredPlatform.getPlatformInterworkingInterfaceAddress());
        assertEquals(ManagementStatus.OK, platformRegistrationResponse.getRegistrationStatus());
    }

    @Test
    public void platformRegistrationFailWrongPlatformId() {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP without preferred platform identifier
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                "Wrong_platform#id",
                OperationType.CREATE);
        // issue platform registration
        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException e) {
            assertEquals(ServiceManagementException.AWKWARD_SERVICE, e.getMessage());
        }
    }

    @Test
    public void platformManageMissingCredentials() {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));
        // issue platform registration without platform owner username
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials("", platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException e) {
            assertEquals(InvalidArgumentsException.MISSING_CREDENTIAL, e.getMessage());
        }

        platformManagementRequest = new PlatformManagementRequest(
                null,
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException e) {
            assertEquals(InvalidArgumentsException.MISSING_CREDENTIALS, e.getMessage());
        }
    }

    @Test
    public void platformManageFailNotExistingUser() {
        // verify that our platformOwner is in repository
        assertFalse(userRepository.exists(wrongUsername));
        // issue platform registration with wrong platform owner username
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(wrongUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException e) {
            assertEquals(new NotExistingUserException().getErrorMessage(), e.getErrorMessage());
        }
    }

    @Test
    public void platformManageFailWrongPlatformOwner() throws
            SecurityException {
        // verify that  platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));
        //create the platform by platformOwner
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);
        PlatformManagementResponse platformManagementResponse = platformsManagementService.authManage(platformManagementRequest);
        assertEquals(ManagementStatus.OK, platformManagementResponse.getRegistrationStatus());

        // create other platformOwner
        String otherPlatformOwnerUsername = "otherPlatformOwner";
        User otherPlatformOwner = createUser(otherPlatformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(otherPlatformOwner);
        Credentials otherPlatformOwnerCredentials = new Credentials(otherPlatformOwnerUsername, platformOwnerPassword);
        // verify that other platformOwner is in repository
        assertTrue(userRepository.exists(otherPlatformOwnerUsername));

        //try to update platform by other platformOwner (without rights to this platform)
        platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                otherPlatformOwnerCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.UPDATE);
        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException e) {
            assertEquals(ServiceManagementException.NOT_OWNED_SERVICE, e.getMessage());
        }

        //try to delete platform by other platformOwner (without rights to this platform)
        platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                otherPlatformOwnerCredentials,
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.DELETE);
        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException e) {
            assertEquals(ServiceManagementException.NOT_OWNED_SERVICE, e.getMessage());
        }
    }

    @Test
    public void platformManageFailWrongPassword() {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, wrongPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException e) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), e.getErrorMessage());
        }
    }

    @Test
    public void platformRegistrationFailWrongInterfaceAddress() {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                coreInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException e) {
            assertEquals(ServiceManagementException.AWKWARD_SERVICE, e.getMessage());
        }
    }

    @Test
    public void platformManageFailUserNotPlatformOwner() {
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        assertTrue(userRepository.exists(username));
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, password),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), errorResponse.getErrorMessage());
        }
    }

    @Test
    public void platformRegistrationFailureUnauthorized() {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration expecting with wrong AAMOwnerUsername
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername + "wrong", AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), errorResponse.getErrorMessage());
        }
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));


        // issue platform registration over AMQP expecting with wrong AAMOwnerPassword
        platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword + "wrong"),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), errorResponse.getErrorMessage());
        }
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
    }

    @Test
    public void platformRegistrationFailureMissingAAMURL() {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration without required Platform's AAM URL
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                "",
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(InvalidArgumentsException.MISSING_PLATFORM_AAM_URL, errorResponse.getMessage());
        }
    }

    @Test
    public void platformRegistrationFailureMissingFriendlyName() {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration without friendly name
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                "",
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(InvalidArgumentsException.MISSING_INSTANCE_FRIENDLY_NAME, errorResponse.getMessage());
        }
    }

    @Test
    public void platformRegistrationFailurePreferredPlatformIdExists() throws SecurityException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        PlatformManagementResponse platformManagementResponse = platformsManagementService.authManage(platformManagementRequest);
        assertEquals(preferredPlatformId, platformManagementResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        User user = createUser(platformOwnerUsername + "differentOne", platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(user);
        // issue registration request with the same preferred platform identifier but different PO
        platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername + "differentOne", platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(ServiceManagementException.SERVICE_EXISTS, errorResponse.getMessage());
        }
    }

    @Test
    public void platformRegistrationFailurePlatformInterworkingInterfaceInUseByAnotherPlatform() throws
            SecurityException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        // issue platform registration
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        PlatformManagementResponse platformManagementResponse = platformsManagementService.authManage(platformManagementRequest);
        assertEquals(preferredPlatformId, platformManagementResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        // issue registration request with the same platformInterworkingInterfaceAddress
        platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId + "differentOne",
                OperationType.CREATE);

        // we try to use the same Interworking Interface!
        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, errorResponse.getMessage());
        }
    }

    @Test
    public void platformRegistrationFailurePlatformInterworkingInterfaceInUseByAnotherSmartSpace() throws
            SecurityException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        // put smart space with platformInterworkingInterfaceAddress into repo
        smartSpaceRepository.save(new SmartSpace(preferredSmartSpaceId,
                smartSpaceInstanceFriendlyName,
                platformInterworkingInterfaceAddress,
                isExposingSiteLocalAddress,
                smartSpaceSiteLocalAddress,
                new Certificate(),
                new HashMap<>(),
                userRepository.findOne(platformOwnerUsername)));

        // issue registration request with the same platformInterworkingInterfaceAddress
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, errorResponse.getMessage());
        }
    }

    @Test
    public void platformUpdateSuccess() throws SecurityException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        PlatformManagementResponse platformManagementResponse = platformsManagementService.authManage(platformManagementRequest);
        //ensure platform is registered
        assertEquals(ManagementStatus.OK, platformManagementResponse.getRegistrationStatus());

        platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,// + "differentOne",
                platformInstanceFriendlyName + "differentOne",
                preferredPlatformId,
                OperationType.UPDATE);

        platformManagementResponse = platformsManagementService.authManage(platformManagementRequest);
        assertEquals(ManagementStatus.OK, platformManagementResponse.getRegistrationStatus());
    }

    @Test
    public void platformUpdateFailNotExistingPlatform() {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                platformId,
                OperationType.UPDATE);
        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(ServiceManagementException.SERVICE_NOT_EXIST, errorResponse.getMessage());
        }
    }

    @Test
    public void platformUpdateFailureCoreInterfaceAddressUsed() throws
            SecurityException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        // issue platform registration
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        PlatformManagementResponse platformManagementResponse = platformsManagementService.authManage(platformManagementRequest);
        assertEquals(preferredPlatformId, platformManagementResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        // update platform to contain coreInterworkingInterface
        platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                coreInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.UPDATE);
        // we try to use core Interworking Interface!
        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(ServiceManagementException.AWKWARD_SERVICE, errorResponse.getMessage());
        }
    }

    @Test
    public void platformUpdateFailurePlatformInterworkingInterfaceInUseByAnotherPlatform() throws
            SecurityException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        // issue platform registration
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        PlatformManagementResponse platformManagementResponse = platformsManagementService.authManage(platformManagementRequest);
        assertEquals(preferredPlatformId, platformManagementResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        // issue platform registration
        platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress + "dif",
                platformInstanceFriendlyName,
                preferredPlatformId + "dif",
                OperationType.CREATE);

        platformManagementResponse = platformsManagementService.authManage(platformManagementRequest);
        assertEquals(preferredPlatformId + "dif", platformManagementResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));

        // issue platform update with the same platformInterworkingInterfaceAddress
        platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId + "dif",
                OperationType.UPDATE);

        // we try to use the same Interworking Interface!
        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, errorResponse.getMessage());
        }
    }

    @Test
    public void platformUpdateFailurePlatformInterworkingInterfaceInUseByAnotherService() throws
            SecurityException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        smartSpaceRepository.save(new SmartSpace(preferredSmartSpaceId,
                smartSpaceInstanceFriendlyName,
                platformInterworkingInterfaceAddress,
                isExposingSiteLocalAddress,
                smartSpaceSiteLocalAddress,
                new Certificate(),
                new HashMap<>(),
                userRepository.findOne(platformOwnerUsername)));

        // issue platform registration
        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress + "2",
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        PlatformManagementResponse platformManagementResponse = platformsManagementService.authManage(platformManagementRequest);
        assertEquals(preferredPlatformId, platformManagementResponse.getPlatformId());
        assertNotNull(platformRepository.findOne(preferredPlatformId));


        // issue platform update with the same platformInterworkingInterfaceAddress
        platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.UPDATE);

        // we try to use the same Interworking Interface!
        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, errorResponse.getMessage());
        }
    }

    @Test
    public void platformDeleteSuccessAndKeyRemoved() throws
            SecurityException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId,
                OperationType.CREATE);

        PlatformManagementResponse platformManagementResponse = platformsManagementService.authManage(platformManagementRequest);
        //ensure platform is registered
        assertEquals(ManagementStatus.OK, platformManagementResponse.getRegistrationStatus());

        Platform platform = platformRepository.findOne(preferredPlatformId);
        X509Certificate platformCertificate = getCertificateFromTestKeystore(
                "keystores/platform_1.p12",
                "platform-1-1-c1");
        platform.setPlatformAAMCertificate(new Certificate(
                CryptoHelper.convertX509ToPEM(platformCertificate)));
        assertFalse(revokedKeysRepository.exists(preferredPlatformId));
        platformRepository.save(platform);
        // delete platform 1
        platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                "",
                "",
                preferredPlatformId,
                OperationType.DELETE);
        assertEquals(ManagementStatus.OK, platformsManagementService.authManage(platformManagementRequest).getRegistrationStatus());
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(revokedKeysRepository.exists(preferredPlatformId));
        assertTrue(revokedKeysRepository.findOne(preferredPlatformId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(platformCertificate.getPublicKey().getEncoded())));
        assertTrue(userRepository.findOne(platformOwnerUsername).getOwnedServices().isEmpty());

    }

    @Test
    public void platformDeleteFailNotExistingPlatform() {
        // verify that our platformOwner is in repository
        assertTrue(userRepository.exists(platformOwnerUsername));

        PlatformManagementRequest platformManagementRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(platformOwnerUsername, platformOwnerPassword),
                "",
                "",
                preferredPlatformId,
                OperationType.DELETE);
        try {
            platformsManagementService.authManage(platformManagementRequest);
            fail();
        } catch (SecurityException errorResponse) {
            assertEquals(ServiceManagementException.SERVICE_NOT_EXIST, errorResponse.getMessage());
        }
    }
}
