package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SspManagementException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.SspManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.SspManagementResponse;
import eu.h2020.symbiote.security.repositories.entities.Ssp;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.SspManagementService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class SspManagementUnitTests extends
        AbstractAAMTestSuite {

    private final String preferredSspId = SecurityConstants.SSP_IDENTIFIER_PREFIX + "preferredSspId";
    private final String sspInstanceFriendlyName = "friendlySspName";
    private final String sspExternalInterworkingInterfaceAddress =
            "https://ssp.eu:8101/someFancyHiddenPath/andHiddenAgain";
    private final String sspInternalInterworkingInterfaceAddress =
            "https://ssp.hidden:8101/someFancyHiddenPath";
    private final boolean exposedInternalII = true;
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    String coreInterfaceAddress;
    private Credentials sspOwnerUserCredentials;
    private SspManagementRequest sspManagementRequest;
    @Autowired
    private SspManagementService sspManagementService;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // db cleanup
        sspRepository.deleteAll();
        userRepository.deleteAll();

        //user registration useful
        User user = createUser(sspOwnerUsername, sspOwnerPassword, recoveryMail, UserRole.SSP_OWNER);
        userRepository.save(user);

        // platform registration useful
        sspOwnerUserCredentials = new Credentials(sspOwnerUsername, sspOwnerPassword);
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.CREATE,
                preferredSspId,
                exposedInternalII);
    }


    @Test
    public void sspRegistrationWithPreferredSspIdSuccess() throws
            SecurityException {
        // verify that our ssp is not in repository and that our sspOwner is in repository
        assertFalse(sspRepository.exists(preferredSspId));
        assertTrue(userRepository.exists(sspOwnerUsername));
        User sspOwner = userRepository.findOne(sspOwnerUsername);
        assertTrue(sspOwner.getOwnedServices().isEmpty());

        // issue ssp registration
        SspManagementResponse response = sspManagementService.authManage(sspManagementRequest);

        // verified that we received the preferred sspId
        assertEquals(preferredSspId, response.getSspId());

        // verify that SO is in repository (as SO!)
        User sspOwnerFromRepository = userRepository.findOne(sspOwnerUsername);
        assertNotNull(sspOwnerFromRepository);
        assertEquals(UserRole.SSP_OWNER, sspOwnerFromRepository.getRole());

        // verify that ssp with preferred id is in repository and is tied with the given SO
        Ssp registeredSsp = sspRepository.findOne(preferredSspId);
        assertNotNull(registeredSsp);
        // verify that ssp oriented fields are properly stored
        assertEquals(sspExternalInterworkingInterfaceAddress, registeredSsp.getSspExternalInterworkingInterfaceAddress());
        assertEquals(sspInternalInterworkingInterfaceAddress, registeredSsp.getSspInternalInterworkingInterfaceAddress());
        assertEquals(exposedInternalII, registeredSsp.isExposedInternalInterworkingInterfaceAddress());

        // verify that SO has this ssp in his collection
        User sspOwnerFromSspEntity = registeredSsp.getSspOwner();
        assertEquals(sspOwnerUsername, sspOwnerFromSspEntity.getUsername());
        assertTrue(sspOwnerFromSspEntity.getOwnedServices().contains(preferredSspId));

        // verify that SO was properly updated in repository with new ssp ownership
        sspOwnerFromRepository = userRepository.findOne(sspOwnerUsername);
        assertEquals(sspOwnerUsername, sspOwnerFromRepository.getUsername());
        assertFalse(sspOwnerFromRepository.getOwnedServices().isEmpty());
        assertTrue(sspOwnerFromRepository.getOwnedServices().contains(preferredSspId));

        assertEquals(ManagementStatus.OK, response.getManagementStatus());
    }

    @Test
    public void sspRegistrationWithGeneratedSspIdSuccess() throws
            SecurityException {
        // verify that our sspOwner is in repository
        assertTrue(userRepository.exists(sspOwnerUsername));

        // issue ssp registration without preferred ssp identifier
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.CREATE,
                "",
                exposedInternalII);
        SspManagementResponse sspRegistrationResponse = sspManagementService.authManage(sspManagementRequest);

        // verified that we received a generated sspId
        String generatedSspId = sspRegistrationResponse.getSspId();
        assertFalse(generatedSspId.isEmpty());

        // verify that SO is in repository (as SO!)
        User registeredSspOwner = userRepository.findOne(sspOwnerUsername);
        assertNotNull(registeredSspOwner);
        assertEquals(UserRole.SSP_OWNER, registeredSspOwner.getRole());
        assertTrue(registeredSspOwner.getOwnedServices().contains(generatedSspId));

        // verify that ssp with the generated id is in repository and is tied with the given SO
        Ssp registeredSsp = sspRepository.findOne(generatedSspId);
        assertNotNull(registeredSsp);
        assertEquals(sspOwnerUsername, registeredSsp.getSspOwner().getUsername());

        // verify that ssp oriented fields are properly stored
        assertEquals(sspExternalInterworkingInterfaceAddress, registeredSsp.getSspExternalInterworkingInterfaceAddress());
        assertEquals(sspInternalInterworkingInterfaceAddress, registeredSsp.getSspInternalInterworkingInterfaceAddress());
        assertEquals(exposedInternalII, registeredSsp.isExposedInternalInterworkingInterfaceAddress());
        assertEquals(ManagementStatus.OK, sspRegistrationResponse.getManagementStatus());
    }

    @Test
    public void sspRegistrationFailWrongSspId() {
        // verify that our sspOwner is in repository
        assertTrue(userRepository.exists(sspOwnerUsername));

        // issue ssp registration with wrong preferred ssp identifier (no "SSP_" prefix)
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.CREATE,
                "NO_SSP_in_front_id",
                exposedInternalII);
        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(InvalidArgumentsException.NO_SSP_PREFIX, s.getMessage());
        }
        // issue ssp registration with wrong preferred ssp identifier (containing "#")
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.CREATE,
                SecurityConstants.SSP_IDENTIFIER_PREFIX + "Wrong#ssp_id",
                exposedInternalII);

        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(SspManagementException.AWKWARD_SSP, s.getMessage());
        }

    }

    @Test
    public void sspManagementFailMissingCredentials() {
        // verify that our sspOwner is in repository
        assertTrue(userRepository.exists(sspOwnerUsername));
        sspManagementRequest.getSspOwnerCredentials().setUsername("");

        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(InvalidArgumentsException.MISSING_USERNAME_OR_PASSWORD, s.getMessage());
        }
    }

    @Test
    public void sspManageFailNotExistingUser() {
        // verify that our sspOwner is in repository
        assertFalse(userRepository.exists(wrongUsername));
        sspManagementRequest.getSspOwnerCredentials().setUsername(wrongUsername);

        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(new NotExistingUserException().getErrorMessage(), s.getErrorMessage());
        }
    }

    @Test
    public void sspManageFailWrongSO() throws SecurityException {
        // verify that  sspOwner is in repository
        assertTrue(userRepository.exists(sspOwnerUsername));
        //create the ssp by sspOwner
        SspManagementResponse sspManagementResponse = sspManagementService.authManage(sspManagementRequest);
        assertEquals(ManagementStatus.OK, sspManagementResponse.getManagementStatus());

        // create other sspOwner
        String othersspOwnerUsername = "otherSspOwner";
        User otherSspOwner = createUser(othersspOwnerUsername, sspOwnerPassword, recoveryMail, UserRole.SSP_OWNER);
        userRepository.save(otherSspOwner);
        Credentials otherSspOwnerCredentials = new Credentials(othersspOwnerUsername, sspOwnerPassword);
        // verify that other sspOwner is in repository
        assertTrue(userRepository.exists(othersspOwnerUsername));

        //try to update ssp by other sspOwner (without rights to this ssp)
        SspManagementRequest sspUpdateRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                otherSspOwnerCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.UPDATE,
                preferredSspId,
                exposedInternalII);
        try {
            sspManagementService.authManage(sspUpdateRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(SspManagementException.USER_IS_NOT_A_SSP_OWNER, s.getMessage());
        }

        //try to delete ssp by other sspOwner (without rights to this ssp)
        SspManagementRequest sspDeleteRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                otherSspOwnerCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.DELETE,
                preferredSspId,
                exposedInternalII);
        try {
            sspManagementService.authManage(sspDeleteRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(SspManagementException.USER_IS_NOT_A_SSP_OWNER, s.getMessage());
        }
    }

    @Test
    public void sspManagementFailWrongPassword() {
        // verify that our sspOwner is in repository
        assertTrue(userRepository.exists(sspOwnerUsername));
        sspManagementRequest.getSspOwnerCredentials().setPassword(wrongPassword);

        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), s.getErrorMessage());
        }
    }

    @Test
    public void sspManagementFailUserNotSspOwner() {
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        assertTrue(userRepository.exists(username));
        sspManagementRequest.getSspOwnerCredentials().setUsername(username);
        sspManagementRequest.getSspOwnerCredentials().setPassword(password);
        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), s.getErrorMessage());
        }
    }

    @Test
    public void sspRegistrationFailUnauthorized() {
        // verify that our ssp is not in repository and that our sspOwner is in repository
        assertFalse(sspRepository.exists(preferredSspId));
        assertTrue(userRepository.exists(sspOwnerUsername));

        // issue ssp registration with wrong AAMOwnerUsername
        sspManagementRequest.getAamOwnerCredentials().setUsername(AAMOwnerUsername + "somethingWrong");
        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), s.getErrorMessage());
        }
        // verify that our ssp is not in repository and that our sspOwner is in repository
        assertFalse(sspRepository.exists(preferredSspId));
        assertTrue(userRepository.exists(sspOwnerUsername));

        // issue ssp registration with wrong AAMOwnerPassword
        sspManagementRequest.getAamOwnerCredentials().setUsername(AAMOwnerUsername);
        sspManagementRequest.getAamOwnerCredentials().setPassword(AAMOwnerPassword + "somethingWrong");
        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), s.getErrorMessage());
        }

        // verify that our ssp is not in repository and that our sspOwner is in repository
        assertFalse(sspRepository.exists(preferredSspId));
        assertTrue(userRepository.exists(sspOwnerUsername));
    }

    @Test
    public void sspRegistrationFailMissingExposedURL() {
        // verify that our ssp is not in repository and that our sspOwner is in repository
        assertFalse(sspRepository.exists(preferredSspId));
        assertTrue(userRepository.exists(sspOwnerUsername));

        // issue ssp registration without exposed II
        SspManagementRequest sspCreateRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                "",
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.CREATE,
                preferredSspId,
                false);

        try {
            sspManagementService.authManage(sspCreateRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(InvalidArgumentsException.MISSING_EXPOSED_INTERWORKING_INTERFACE, s.getMessage());
        }
        // issue ssp registration without exposed II
        sspCreateRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                "",
                sspInstanceFriendlyName,
                OperationType.CREATE,
                preferredSspId,
                true);

        try {
            sspManagementService.authManage(sspCreateRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(InvalidArgumentsException.MISSING_EXPOSED_INTERWORKING_INTERFACE, s.getMessage());
        }

    }

    @Test
    public void sspUpdateFailMissingExposedURL() throws SecurityException {
        // verify that our ssp is not in repository and that our sspOwner is in repository
        assertFalse(sspRepository.exists(preferredSspId));
        assertTrue(userRepository.exists(sspOwnerUsername));

        //register SSP with exposed internal II - external is empty
        sspManagementRequest.setSspExternalInterworkingInterfaceAddress("");
        SspManagementResponse sspManagementResponse = sspManagementService.authManage(sspManagementRequest);
        assertEquals(ManagementStatus.OK, sspManagementResponse.getManagementStatus());

        // issue ssp update without exposed II
        SspManagementRequest sspUpdateRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                "",
                "",
                sspInstanceFriendlyName,
                OperationType.UPDATE,
                preferredSspId,
                false);

        try {
            sspManagementService.authManage(sspUpdateRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(InvalidArgumentsException.MISSING_EXPOSED_INTERWORKING_INTERFACE, s.getMessage());
        }
    }

    @Test
    public void sspRegistrationFailMissingFriendlyName() {
        // verify that our ssp is not in repository and that our sspOwner is in repository
        assertFalse(sspRepository.exists(preferredSspId));
        assertTrue(userRepository.exists(sspOwnerUsername));

        // issue ssp registration without required Ssp's instance friendly name
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                "",
                OperationType.CREATE,
                preferredSspId,
                true);
        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(InvalidArgumentsException.MISSING_INSTANCE_FRIENDLY_NAME, s.getMessage());
        }
    }

    @Test
    public void sspRegistrationFailExistingPreferredSspId() throws SecurityException {
        // verify that our ssp is not in repository and that our sspOwner is in repository
        assertFalse(sspRepository.exists(preferredSspId));
        assertTrue(userRepository.exists(sspOwnerUsername));

        // issue ssp registration
        SspManagementResponse sspManagementResponse = sspManagementService.authManage(sspManagementRequest);
        assertEquals(ManagementStatus.OK, sspManagementResponse.getManagementStatus());

        assertNotNull(sspRepository.findOne(preferredSspId));

        User user = createUser(sspOwnerUsername + "differentOne", sspOwnerPassword, recoveryMail, UserRole.SSP_OWNER);
        userRepository.save(user);
        // issue registration request with the same preferred ssp identifier but different SO
        sspManagementRequest.getSspOwnerCredentials().setUsername
                (sspOwnerUsername + "differentOne");
        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(SspManagementException.SSP_EXISTS, s.getMessage());
        }
    }
    @Test
    public void sspUpdateSuccess() throws SecurityException {
        // verify that our sspOwner is in repository
        assertTrue(userRepository.exists(sspOwnerUsername));
        //register ssp
        SspManagementResponse sspRegistrationResponse = sspManagementService.authManage(sspManagementRequest);
        //ensure ssp is registered
        assertEquals(ManagementStatus.OK, sspRegistrationResponse.getManagementStatus());

        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress + "dif",
                sspInternalInterworkingInterfaceAddress + "dif",
                sspInstanceFriendlyName,
                OperationType.UPDATE,
                preferredSspId,
                !exposedInternalII);
        sspRegistrationResponse = sspManagementService.authManage(sspManagementRequest);
        //ensure ssp is registered
        assertEquals(ManagementStatus.OK, sspRegistrationResponse.getManagementStatus());
        // verify that SO was properly updated in repository with new ssp ownership
        Ssp registeredSsp = sspRepository.findOne(preferredSspId);
        assertNotNull(registeredSsp);
        // verify that ssp oriented fields are properly stored
        assertEquals(sspExternalInterworkingInterfaceAddress + "dif", registeredSsp.getSspExternalInterworkingInterfaceAddress());
        assertEquals(sspInternalInterworkingInterfaceAddress + "dif", registeredSsp.getSspInternalInterworkingInterfaceAddress());
        assertEquals(!exposedInternalII, registeredSsp.isExposedInternalInterworkingInterfaceAddress());
    }

    @Test
    public void sspUpdateFailNotExistingSsp() {
        // verify that our sspOwner is in repository
        assertTrue(userRepository.exists(sspOwnerUsername));
        // verify that our ssp is not in repository
        assertFalse(sspRepository.exists(preferredSspId));

        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.UPDATE,
                preferredSspId,
                !exposedInternalII);

        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(SspManagementException.SSP_NOT_EXIST, s.getMessage());
        }
    }

    @Test
    public void sspDeleteSuccess() throws
            SecurityException {
        // verify that our sspOwner is in repository
        assertTrue(userRepository.exists(sspOwnerUsername));
        //register ssp
        SspManagementResponse sspRegistrationResponse = sspManagementService.authManage(sspManagementRequest);
        //ensure ssp is registered
        assertEquals(ManagementStatus.OK, sspRegistrationResponse.getManagementStatus());

        //register second ssp
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress + "2",
                sspInternalInterworkingInterfaceAddress + "2",
                sspInstanceFriendlyName,
                OperationType.CREATE,
                preferredSspId + "2",
                exposedInternalII);
        sspRegistrationResponse = sspManagementService.authManage(sspManagementRequest);
        //ensure second ssp is registered
        assertEquals(ManagementStatus.OK, sspRegistrationResponse.getManagementStatus());

        // delete ssp 1
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                "",
                "",
                "",
                OperationType.DELETE,
                preferredSspId,
                exposedInternalII);
        sspRegistrationResponse = sspManagementService.authManage(sspManagementRequest);
        assertEquals(ManagementStatus.OK, sspRegistrationResponse.getManagementStatus());
        assertFalse(sspRepository.exists(preferredSspId));
        assertTrue(sspRepository.exists(preferredSspId + "2"));

        // delete ssp 2
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                "",
                "",
                "",
                OperationType.DELETE,
                preferredSspId + "2",
                exposedInternalII);
        sspRegistrationResponse = sspManagementService.authManage(sspManagementRequest);
        assertEquals(ManagementStatus.OK, sspRegistrationResponse.getManagementStatus());
        assertFalse(sspRepository.exists(preferredSspId + "2"));

        assertTrue(userRepository.findOne(sspOwnerUsername).getOwnedServices().isEmpty());
    }

    @Test
    public void sspDeleteFailNotExistingSsp() {
        // verify that our sspOwner is in repository
        assertTrue(userRepository.exists(sspOwnerUsername));
        assertFalse(sspRepository.exists(preferredSspId));
        // delete not existing platform
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.DELETE,
                preferredSspId,
                exposedInternalII);
        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(SspManagementException.SSP_NOT_EXIST, s.getMessage());
        }
    }
    @Test
    public void sspRegistrationFailExistingInterworkingInterface() throws SecurityException {
        // verify that our sspOwner is in repository
        assertTrue(userRepository.exists(sspOwnerUsername));
        //register ssp
        SspManagementResponse sspRegistrationResponse = sspManagementService.authManage(sspManagementRequest);
        //ensure ssp is registered
        assertEquals(ManagementStatus.OK, sspRegistrationResponse.getManagementStatus());

        //register ssp with exposed external II
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.CREATE,
                preferredSspId + "_external",
                !exposedInternalII);
        sspRegistrationResponse = sspManagementService.authManage(sspManagementRequest);
        //ensure ssp is registered
        assertEquals(ManagementStatus.OK, sspRegistrationResponse.getManagementStatus());

        //try to register ssp with the same exposed internal interface
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                "",
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.CREATE,
                preferredSspId + "1",
                exposedInternalII);
        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(SspManagementException.SSP_INTERWARKING_INTERFACE_IN_USE, s.getMessage());
        }

        //try to register ssp with the same exposed external interface
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                "",
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.CREATE,
                preferredSspId + "2",
                exposedInternalII);
        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(SspManagementException.SSP_INTERWARKING_INTERFACE_IN_USE, s.getMessage());
        }

    }

    @Test
    public void sspUpdateFailExistingInterworkingInterface() throws SecurityException {
        // verify that our sspOwner is in repository
        assertTrue(userRepository.exists(sspOwnerUsername));
        //register ssp
        SspManagementResponse sspRegistrationResponse = sspManagementService.authManage(sspManagementRequest);
        //ensure ssp is registered
        assertEquals(ManagementStatus.OK, sspRegistrationResponse.getManagementStatus());

        //register ssp with exposed external II
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.CREATE,
                preferredSspId + "_external",
                !exposedInternalII);
        sspRegistrationResponse = sspManagementService.authManage(sspManagementRequest);
        //ensure ssp is registered
        assertEquals(ManagementStatus.OK, sspRegistrationResponse.getManagementStatus());

        //try to update first ssp to expose the same internal interface as second one
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.UPDATE,
                preferredSspId + "_external",
                exposedInternalII);
        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(SspManagementException.SSP_INTERWARKING_INTERFACE_IN_USE, s.getMessage());
        }

        //try to update first ssp to expose the same internal interface as second one
        sspManagementRequest = new SspManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                sspOwnerUserCredentials,
                sspExternalInterworkingInterfaceAddress,
                sspInternalInterworkingInterfaceAddress,
                sspInstanceFriendlyName,
                OperationType.UPDATE,
                preferredSspId,
                !exposedInternalII);
        try {
            sspManagementService.authManage(sspManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(SspManagementException.SSP_INTERWARKING_INTERFACE_IN_USE, s.getMessage());
        }

    }

}
