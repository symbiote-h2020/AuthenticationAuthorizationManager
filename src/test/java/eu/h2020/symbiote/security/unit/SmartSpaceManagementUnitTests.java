package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ServiceManagementException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.SmartSpaceManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.SmartSpaceManagementResponse;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.SmartSpacesManagementService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class SmartSpaceManagementUnitTests extends
        AbstractAAMTestSuite {

    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    String coreInterfaceAddress;
    private Credentials smartSpaceOwnerUserCredentials;
    private SmartSpaceManagementRequest smartSpaceManagementRequest;
    @Autowired
    private SmartSpacesManagementService smartSpacesManagementService;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // db cleanup
        smartSpaceRepository.deleteAll();
        userRepository.deleteAll();

        //user registration useful
        User user = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.NEW);
        userRepository.save(user);

        // platform registration useful
        smartSpaceOwnerUserCredentials = new Credentials(smartSpaceOwnerUsername, smartSpaceOwnerPassword);
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.CREATE,
                preferredSmartSpaceId,
                isExposingSiteLocalAddress);
    }


    @Test
    public void smartSpaceRegistrationWithPreferredSmartSpaceIdSuccess() throws
            SecurityException {
        // verify that our smartSpace is not in repository and that our smartSpaceOwner is in repository
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId));
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
        User smartSpaceOwner = userRepository.findOne(smartSpaceOwnerUsername);
        assertTrue(smartSpaceOwner.getOwnedServices().isEmpty());

        // issue smartSpace registration
        SmartSpaceManagementResponse response = smartSpacesManagementService.authManage(smartSpaceManagementRequest);

        // verified that we received the preferred smartSpaceId
        assertEquals(preferredSmartSpaceId, response.getSmartSpaceId());

        // verify that SO is in repository (as SO!)
        User smartSpaceOwnerFromRepository = userRepository.findOne(smartSpaceOwnerUsername);
        assertNotNull(smartSpaceOwnerFromRepository);
        assertEquals(UserRole.SERVICE_OWNER, smartSpaceOwnerFromRepository.getRole());

        // verify that smartSpace with preferred id is in repository and is tied with the given SO
        SmartSpace registeredSmartSpace = smartSpaceRepository.findOne(preferredSmartSpaceId);
        assertNotNull(registeredSmartSpace);
        // verify that smartSpace oriented fields are properly stored
        assertEquals(smartSpaceGateWayAddress, registeredSmartSpace.getExternalAddress());
        assertEquals(smartSpaceSiteLocalAddress, registeredSmartSpace.getSiteLocalAddress());
        assertEquals(isExposingSiteLocalAddress, registeredSmartSpace.isExposingSiteLocalAddress());

        // verify that SO has this smartSpace in his collection
        User smartSpaceOwnerFromSmartSpaceEntity = registeredSmartSpace.getSmartSpaceOwner();
        assertEquals(smartSpaceOwnerUsername, smartSpaceOwnerFromSmartSpaceEntity.getUsername());
        assertTrue(smartSpaceOwnerFromSmartSpaceEntity.getOwnedServices().contains(preferredSmartSpaceId));

        // verify that SO was properly updated in repository with new smartSpace ownership
        smartSpaceOwnerFromRepository = userRepository.findOne(smartSpaceOwnerUsername);
        assertEquals(smartSpaceOwnerUsername, smartSpaceOwnerFromRepository.getUsername());
        assertFalse(smartSpaceOwnerFromRepository.getOwnedServices().isEmpty());
        assertTrue(smartSpaceOwnerFromRepository.getOwnedServices().contains(preferredSmartSpaceId));

        assertEquals(ManagementStatus.OK, response.getManagementStatus());
    }

    @Test
    public void smartSpaceRegistrationWithGeneratedSmartSpaceIdSuccess() throws
            SecurityException {
        // verify that our smartSpaceOwner is in repository
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));

        // issue smartSpace registration without preferred smartSpace identifier
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.CREATE,
                "",
                isExposingSiteLocalAddress);
        SmartSpaceManagementResponse smartSpaceRegistrationResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);

        // verified that we received a generated smartSpaceId
        String generatedSmartSpaceId = smartSpaceRegistrationResponse.getSmartSpaceId();
        assertFalse(generatedSmartSpaceId.isEmpty());

        // verify that SO is in repository (as SO!)
        User registeredSmartSpaceOwner = userRepository.findOne(smartSpaceOwnerUsername);
        assertNotNull(registeredSmartSpaceOwner);
        assertEquals(UserRole.SERVICE_OWNER, registeredSmartSpaceOwner.getRole());
        assertTrue(registeredSmartSpaceOwner.getOwnedServices().contains(generatedSmartSpaceId));

        // verify that smartSpace with the generated id is in repository and is tied with the given SO
        SmartSpace registeredSmartSpace = smartSpaceRepository.findOne(generatedSmartSpaceId);
        assertNotNull(registeredSmartSpace);
        assertEquals(smartSpaceOwnerUsername, registeredSmartSpace.getSmartSpaceOwner().getUsername());

        // verify that smartSpace oriented fields are properly stored
        assertEquals(smartSpaceGateWayAddress, registeredSmartSpace.getExternalAddress());
        assertEquals(smartSpaceSiteLocalAddress, registeredSmartSpace.getSiteLocalAddress());
        assertEquals(isExposingSiteLocalAddress, registeredSmartSpace.isExposingSiteLocalAddress());
        assertEquals(ManagementStatus.OK, smartSpaceRegistrationResponse.getManagementStatus());
    }

    @Test
    public void smartSpaceRegistrationFailWrongSmartSpaceId() throws InvalidArgumentsException {
        // verify that our smartSpaceOwner is in repository
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));

        // issue smartSpace registration with wrong preferred smartSpace identifier (no "SSP_" prefix)
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.CREATE,
                "NO_SSP_in_front_id",
                isExposingSiteLocalAddress);
        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(InvalidArgumentsException.NO_SSP_PREFIX, s.getMessage());
        }
        // issue smartSpace registration with wrong preferred smartSpace identifier (containing "#")
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.CREATE,
                SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX + "Wrong#smartSpace_id",
                isExposingSiteLocalAddress);

        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(ServiceManagementException.AWKWARD_SERVICE, s.getMessage());
        }

    }

    @Test
    public void smartSpaceManagementFailMissingCredentials() {
        // verify that our smartSpaceOwner is in repository
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
        smartSpaceManagementRequest.getServiceOwnerCredentials().setUsername("");

        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(InvalidArgumentsException.MISSING_CREDENTIAL, s.getMessage());
        }
    }

    @Test
    public void smartSpaceManageFailNotExistingUser() {
        // verify that our smartSpaceOwner is in repository
        assertFalse(userRepository.exists(wrongUsername));
        smartSpaceManagementRequest.getServiceOwnerCredentials().setUsername(wrongUsername);

        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(new NotExistingUserException().getErrorMessage(), s.getErrorMessage());
        }
    }

    @Test
    public void smartSpaceManageFailWrongSO() throws SecurityException {
        // verify that  smartSpaceOwner is in repository
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
        //create the smartSpace by smartSpaceOwner
        SmartSpaceManagementResponse smartSpaceManagementResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);
        assertEquals(ManagementStatus.OK, smartSpaceManagementResponse.getManagementStatus());

        // create other smartSpaceOwner
        String otherSmartSpaceOwnerUsername = "otherSmartSpaceOwner";
        User otherSmartSpaceOwner = createUser(otherSmartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.NEW);
        userRepository.save(otherSmartSpaceOwner);
        Credentials otherSmartSpaceOwnerCredentials = new Credentials(otherSmartSpaceOwnerUsername, smartSpaceOwnerPassword);
        // verify that other smartSpaceOwner is in repository
        assertTrue(userRepository.exists(otherSmartSpaceOwnerUsername));

        //try to update smartSpace by other smartSpaceOwner (without rights to this smartSpace)
        SmartSpaceManagementRequest smartSpaceUpdateRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                otherSmartSpaceOwnerCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.UPDATE,
                preferredSmartSpaceId,
                isExposingSiteLocalAddress);
        try {
            smartSpacesManagementService.authManage(smartSpaceUpdateRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(ServiceManagementException.USER_IS_NOT_A_SERVICE_OWNER, s.getMessage());
        }

        //try to delete smartSpace by other smartSpaceOwner (without rights to this smartSpace)
        SmartSpaceManagementRequest smartSpaceDeleteRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                otherSmartSpaceOwnerCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.DELETE,
                preferredSmartSpaceId,
                isExposingSiteLocalAddress);
        try {
            smartSpacesManagementService.authManage(smartSpaceDeleteRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(ServiceManagementException.USER_IS_NOT_A_SERVICE_OWNER, s.getMessage());
        }
    }

    @Test
    public void smartSpaceManagementFailWrongPassword() {
        // verify that our smartSpaceOwner is in repository
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
        smartSpaceManagementRequest.getServiceOwnerCredentials().setPassword(wrongPassword);

        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), s.getErrorMessage());
        }
    }

    @Test
    public void smartSpaceManagementFailUserNotSmartSpaceOwner() {
        User user = createUser(username, password, recoveryMail, UserRole.USER, AccountStatus.NEW);
        userRepository.save(user);
        assertTrue(userRepository.exists(username));
        smartSpaceManagementRequest.getServiceOwnerCredentials().setUsername(username);
        smartSpaceManagementRequest.getServiceOwnerCredentials().setPassword(password);
        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), s.getErrorMessage());
        }
    }

    @Test
    public void smartSpaceRegistrationFailUnauthorized() {
        // verify that our smartSpace is not in repository and that our smartSpaceOwner is in repository
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId));
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));

        // issue smartSpace registration with wrong AAMOwnerUsername
        smartSpaceManagementRequest.getAamOwnerCredentials().setUsername(AAMOwnerUsername + "somethingWrong");
        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), s.getErrorMessage());
        }
        // verify that our smartSpace is not in repository and that our smartSpaceOwner is in repository
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId));
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));

        // issue smartSpace registration with wrong AAMOwnerPassword
        smartSpaceManagementRequest.getAamOwnerCredentials().setUsername(AAMOwnerUsername);
        smartSpaceManagementRequest.getAamOwnerCredentials().setPassword(AAMOwnerPassword + "somethingWrong");
        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(new WrongCredentialsException().getErrorMessage(), s.getErrorMessage());
        }

        // verify that our smartSpace is not in repository and that our smartSpaceOwner is in repository
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId));
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
    }

    @Test
    public void smartSpaceRegistrationFailMissingExposedURL() {
        // verify that our smartSpace is not in repository and that our smartSpaceOwner is in repository
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId));
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));

        // issue smartSpace registration without exposed II
        try {
            SmartSpaceManagementRequest smartSpaceCreateRequest = new SmartSpaceManagementRequest(
                    new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                    smartSpaceOwnerUserCredentials,
                    smartSpaceGateWayAddress,
                    "",
                    smartSpaceInstanceFriendlyName,
                    OperationType.CREATE,
                    preferredSmartSpaceId,
                    true);


            smartSpacesManagementService.authManage(smartSpaceCreateRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(InvalidArgumentsException.MISSING_SITE_LOCAL_ADDRESS, s.getMessage());
        }
    }

    @Test
    public void smartSpaceRegistrationFailMissingFriendlyName() throws InvalidArgumentsException {
        // verify that our smartSpace is not in repository and that our smartSpaceOwner is in repository
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId));
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));

        // issue smartSpace registration without required SmartSpace's instance friendly name
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                "",
                OperationType.CREATE,
                preferredSmartSpaceId,
                true);
        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(InvalidArgumentsException.MISSING_INSTANCE_FRIENDLY_NAME, s.getMessage());
        }
    }

    @Test
    public void smartSpaceRegistrationFailExistingPreferredSmartSpaceId() throws SecurityException {
        // verify that our smartSpace is not in repository and that our smartSpaceOwner is in repository
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId));
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));

        // issue smartSpace registration
        SmartSpaceManagementResponse smartSpaceManagementResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);
        assertEquals(ManagementStatus.OK, smartSpaceManagementResponse.getManagementStatus());

        assertNotNull(smartSpaceRepository.findOne(preferredSmartSpaceId));

        User user = createUser(smartSpaceOwnerUsername + "differentOne", smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.NEW);
        userRepository.save(user);
        // issue registration request with the same preferred smartSpace identifier but different SO
        smartSpaceManagementRequest.getServiceOwnerCredentials().setUsername
                (smartSpaceOwnerUsername + "differentOne");
        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(ServiceManagementException.SERVICE_EXISTS, s.getMessage());
        }
    }
    @Test
    public void smartSpaceUpdateSuccess() throws SecurityException {
        // verify that our smartSpaceOwner is in repository
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
        //register smartSpace
        SmartSpaceManagementResponse smartSpaceRegistrationResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);
        //ensure smartSpace is registered
        assertEquals(ManagementStatus.OK, smartSpaceRegistrationResponse.getManagementStatus());

        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress + "dif",
                smartSpaceSiteLocalAddress + "dif",
                smartSpaceInstanceFriendlyName,
                OperationType.UPDATE,
                preferredSmartSpaceId,
                !isExposingSiteLocalAddress);
        smartSpaceRegistrationResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);
        //ensure smartSpace is registered
        assertEquals(ManagementStatus.OK, smartSpaceRegistrationResponse.getManagementStatus());
        // verify that SO was properly updated in repository with new smartSpace ownership
        SmartSpace registeredSmartSpace = smartSpaceRepository.findOne(preferredSmartSpaceId);
        assertNotNull(registeredSmartSpace);
        // verify that smartSpace oriented fields are properly stored
        assertEquals(smartSpaceGateWayAddress + "dif", registeredSmartSpace.getExternalAddress());
        assertEquals(smartSpaceSiteLocalAddress + "dif", registeredSmartSpace.getSiteLocalAddress());
        assertEquals(!isExposingSiteLocalAddress, registeredSmartSpace.isExposingSiteLocalAddress());
    }

    @Test
    public void smartSpaceUpdateFailNotExistingSmartSpace() throws InvalidArgumentsException {
        // verify that our smartSpaceOwner is in repository
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
        // verify that our smartSpace is not in repository
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId));

        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.UPDATE,
                preferredSmartSpaceId,
                !isExposingSiteLocalAddress);

        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(ServiceManagementException.SERVICE_NOT_EXIST, s.getMessage());
        }
    }

    @Test
    public void smartSpaceDeleteSuccess() throws
            SecurityException {
        // verify that our smartSpaceOwner is in repository
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
        //register smartSpace
        SmartSpaceManagementResponse smartSpaceRegistrationResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);
        //ensure smartSpace is registered
        assertEquals(ManagementStatus.OK, smartSpaceRegistrationResponse.getManagementStatus());

        //register second smartSpace
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress + "2",
                smartSpaceSiteLocalAddress + "2",
                smartSpaceInstanceFriendlyName,
                OperationType.CREATE,
                preferredSmartSpaceId + "2",
                isExposingSiteLocalAddress);
        smartSpaceRegistrationResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);
        //ensure second smartSpace is registered
        assertEquals(ManagementStatus.OK, smartSpaceRegistrationResponse.getManagementStatus());

        // delete smartSpace 1
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                "",
                "",
                "",
                OperationType.DELETE,
                preferredSmartSpaceId,
                isExposingSiteLocalAddress);
        smartSpaceRegistrationResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);
        assertEquals(ManagementStatus.OK, smartSpaceRegistrationResponse.getManagementStatus());
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId));
        assertTrue(smartSpaceRepository.exists(preferredSmartSpaceId + "2"));

        // delete smartSpace 2
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                "",
                "",
                "",
                OperationType.DELETE,
                preferredSmartSpaceId + "2",
                isExposingSiteLocalAddress);
        smartSpaceRegistrationResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);
        assertEquals(ManagementStatus.OK, smartSpaceRegistrationResponse.getManagementStatus());
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId + "2"));

        assertTrue(userRepository.findOne(smartSpaceOwnerUsername).getOwnedServices().isEmpty());
    }

    @Test
    public void smartSpaceDeleteFailNotExistingSmartSpace() throws InvalidArgumentsException {
        // verify that our smartSpaceOwner is in repository
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
        assertFalse(smartSpaceRepository.exists(preferredSmartSpaceId));
        // delete not existing platform
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.DELETE,
                preferredSmartSpaceId,
                isExposingSiteLocalAddress);
        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(ServiceManagementException.SERVICE_NOT_EXIST, s.getMessage());
        }
    }
    @Test
    public void smartSpaceRegistrationFailExistingInterworkingInterface() throws SecurityException {
        // verify that our smartSpaceOwner is in repository
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
        //register smartSpace
        SmartSpaceManagementResponse smartSpaceRegistrationResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);
        //ensure smartSpace is registered
        assertEquals(ManagementStatus.OK, smartSpaceRegistrationResponse.getManagementStatus());

        //try to register smartSpace with the same gateway address
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.CREATE,
                preferredSmartSpaceId + "2",
                isExposingSiteLocalAddress);
        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, s.getMessage());
        }

    }

    @Test
    public void smartSpaceUpdateFailExistingGateWayAddress() throws SecurityException {
        // verify that our smartSpaceOwner is in repository
        assertTrue(userRepository.exists(smartSpaceOwnerUsername));
        //register smartSpace
        SmartSpaceManagementResponse smartSpaceRegistrationResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);
        //ensure smartSpace is registered
        assertEquals(ManagementStatus.OK, smartSpaceRegistrationResponse.getManagementStatus());

        //register smartSpace with different GateWay address
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress + "/differentOne",
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.CREATE,
                preferredSmartSpaceId + "_external",
                !isExposingSiteLocalAddress);
        smartSpaceRegistrationResponse = smartSpacesManagementService.authManage(smartSpaceManagementRequest);
        //ensure smartSpace is registered
        assertEquals(ManagementStatus.OK, smartSpaceRegistrationResponse.getManagementStatus());

        //try to update first smartSpace to expose the same internal interface as second one
        smartSpaceManagementRequest = new SmartSpaceManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                smartSpaceOwnerUserCredentials,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                smartSpaceInstanceFriendlyName,
                OperationType.UPDATE,
                preferredSmartSpaceId + "_external",
                isExposingSiteLocalAddress);
        try {
            smartSpacesManagementService.authManage(smartSpaceManagementRequest);
            fail();
        } catch (SecurityException s) {
            assertEquals(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, s.getMessage());
        }

    }

}
