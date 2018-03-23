package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class UsersManagementUnitTests extends AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(UsersManagementUnitTests.class);
    private final String recoveryMail = "null@dev.null";

    @Test
    public void userCreateSuccess() throws
            SecurityException,
            CertificateException {
        // verify that user is not in the repository
        assertFalse(userRepository.exists(username));
        // new attributes map
        String key = "key";
        String testCertificate = "testCertificateString";
        Map<String, String> attributes = new HashMap<>();
        attributes.put(key, "attribute");
        Map<String, Certificate> certificateMap = new HashMap<>();
        certificateMap.put(key, new Certificate(testCertificate));
        // manage new user to db
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.USER,
                        attributes,
                        certificateMap)
                , OperationType.CREATE);

        ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);

        // verify that user really is in repository
        User registeredUser = userRepository.findOne(username);
        assertNotNull(registeredUser);
        assertEquals(UserRole.USER, registeredUser.getRole());
        assertEquals(1, registeredUser.getAttributes().size());
        assertTrue(registeredUser.getAttributes().containsKey(key));
        //no passed certs are saved
        assertEquals(0, registeredUser.getClientCertificates().size());
        assertEquals(recoveryMail, registeredUser.getRecoveryMail());
        assertEquals(ManagementStatus.OK, userRegistrationResponse);
    }

    @Test
    public void userCreateSuccessServiceOwnerRegistrationInCoreAAM() throws SecurityException {
        // verify that app is not in the repository
        assertFalse(userRepository.exists(username));
        // manage new user to db with illegal role
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.SERVICE_OWNER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);

        ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);

        // verify that serviceOwner really is in repository
        User registeredUser = userRepository.findOne(username);
        assertNotNull(registeredUser);
        assertEquals(UserRole.SERVICE_OWNER, registeredUser.getRole());
        assertEquals(ManagementStatus.OK, userRegistrationResponse);
    }

    @Test
    public void userCreateSuccessServiceOwnerRegistrationInSmartSpaceAAM() throws SecurityException {
        // verify that app is not in the repository
        assertFalse(userRepository.exists(username));
        // manage new user to db with illegal role
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.SERVICE_OWNER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        try {
            // hack: make sure the AAM thinks it is a smart space AAM
            ReflectionTestUtils.setField(usersManagementService, "deploymentType", IssuingAuthorityType.SMART_SPACE);
            ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);
            // verify that serviceOwner really is in repository
            User registeredUser = userRepository.findOne(username);
            assertNotNull(registeredUser);
            assertEquals(UserRole.SERVICE_OWNER, registeredUser.getRole());
            assertEquals(ManagementStatus.OK, userRegistrationResponse);

        } catch (InvalidArgumentsException e) {
            fail("Exception thrown");
        } finally {
            // reverting to old type
            ReflectionTestUtils.setField(usersManagementService, "deploymentType", certificationAuthorityHelper.getDeploymentType());
        }
    }

    @Test
    public void userCreateFailUserWithAdminCredentials()
            throws SecurityException {
        // manage new user to db with admin username
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(AAMOwnerUsername, password),
                        recoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);
        // verify that we got an error
        assertEquals(ManagementStatus.ERROR, userRegistrationResponse);
        // verify that user not in db
        assertFalse(userRepository.exists(AAMOwnerUsername));
    }

    @Test
    public void userCreateFailUserWithGuestCredentials()
            throws SecurityException {
        // manage new user to db with guest username
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(SecurityConstants.GUEST_NAME, password),
                        recoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);
        // verify that we got an error
        assertEquals(ManagementStatus.ERROR, userRegistrationResponse);
        // verify that user not in db
        assertFalse(userRepository.exists(SecurityConstants.GUEST_NAME));
    }


    @Test
    public void userCreateFailServiceOwnerRegistrationInPlatformAAM() throws SecurityException {
        // verify that app is not in the repository
        assertFalse(userRepository.exists(username));
        // manage new user to db with illegal role
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.SERVICE_OWNER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        try {
            // hack: make sure the AAM thinks it is a platform AAM
            ReflectionTestUtils.setField(usersManagementService, "deploymentType", IssuingAuthorityType.PLATFORM);
            // should throw exception
            usersManagementService.authManage(userManagementRequest);
            fail("Exception not thrown");
        } catch (InvalidArgumentsException e) {
            assertNotNull(e);
        } finally {
            // reverting to old type
            ReflectionTestUtils.setField(usersManagementService, "deploymentType", certificationAuthorityHelper.getDeploymentType());
        }
    }

    @Test(expected = InvalidArgumentsException.class)
    public void userCreateFailWrongUserRole() throws SecurityException {
        // verify that app is not in the repository
        assertFalse(userRepository.exists(username));
        // manage new user to db with illegal role
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.NULL,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);

        usersManagementService.authManage(userManagementRequest);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void userCreateFailIncorrectUsernameFormat() throws SecurityException {
        String incorrectName = "@#$%^";
        // create new user with incorrect username
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(incorrectName, password),
                        recoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test
    public void userCreateFailUsernameExists() throws SecurityException {
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        // manage new user to db
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        ManagementStatus managementStatus = usersManagementService.authManage(userManagementRequest);
        assertEquals(ManagementStatus.USERNAME_EXISTS, managementStatus);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void userCreateFailMissingUsername() throws SecurityException {
        // manage new user to db
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials("", password),
                        recoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        usersManagementService.authManage(userManagementRequest);

    }

    @Test(expected = InvalidArgumentsException.class)
    public void userCreateFailMissingPassword() throws SecurityException {
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        // manage new user to db
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, ""),
                        recoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void userCreateFailMissingRecoveryMail() throws SecurityException {
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        // manage new user to db
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        "",
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void userManagementFailNoAdminCredentials() throws SecurityException {
        // attempt adding new user to database using request without admin credentials
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                null,
                new Credentials(username, password),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        usersManagementService.authManage(userManagementRequest);
    }


    @Test(expected = UserManagementException.class)
    public void userManagementFailWrongAAMOwnerUsername() throws
            SecurityException {
        // create new user with wrong admin username
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials("wrongAAMOwnerUsername", AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test(expected = UserManagementException.class)
    public void userManagementFailWrongAAMOwnerPassword() throws
            SecurityException {

        // create new user with wrong admin username
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, "wrongAAMOwnerPassword"),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        recoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test
    public void userForceUpdateSuccess() throws SecurityException {
        // save user in db
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        // verify that user is in the repository
        assertTrue(userRepository.exists(username));
        String newPassword = "NewPassword";
        assertNotEquals(newPassword, password);
        // update user (new password)
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, newPassword),
                        "",
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.FORCE_UPDATE);
        ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);
        assertEquals(ManagementStatus.OK, userRegistrationResponse);
        // verify that user really is in repository
        User registeredUser = userRepository.findOne(username);
        assertNotNull(registeredUser);
        // verify if password is changed
        assertTrue(passwordEncoder.matches(newPassword, registeredUser.getPasswordEncrypted()));
        // and recovery mail is still the same
        assertEquals(recoveryMail, registeredUser.getRecoveryMail());

        String newRecoveryMail = "newRecoveryMail";
        // update user (new recovery mail)
        userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, ""),
                        newRecoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.FORCE_UPDATE);
        userRegistrationResponse = usersManagementService.authManage(userManagementRequest);
        assertEquals(ManagementStatus.OK, userRegistrationResponse);
        // verify that user really is in repository
        registeredUser = userRepository.findOne(username);
        assertNotNull(registeredUser);
        // verify if recoveryMail is changed
        assertEquals(newRecoveryMail, registeredUser.getRecoveryMail());
        // and password is still the same
        assertTrue(passwordEncoder.matches(newPassword, registeredUser.getPasswordEncrypted()));
    }

    @Test(expected = UserManagementException.class)
    public void userForceUpdateFailUserNotInDB() throws SecurityException {

        assertNull(userRepository.findOne(username));
        String newPassword = "NewPassword";
        // update user who doesn't exist in db
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, newPassword),
                        recoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.FORCE_UPDATE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test
    public void userAttributesUpdateSuccess() throws SecurityException {
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        assertEquals(0, user.getAttributes().size());
        // new attributes map
        String key = "key";
        String attributeValue = "value";
        String newMail = "newMail";
        Map<String, String> attributes = new HashMap<>();
        attributes.put(key, attributeValue);
        // update attributes - new values of mail to check, if they change too
        // wrong password used to check, if it is checked (should not be)
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, ""),
                        newMail,
                        UserRole.USER,
                        attributes,
                        new HashMap<>()),
                OperationType.ATTRIBUTES_UPDATE);
        ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);
        assertEquals(ManagementStatus.OK, userRegistrationResponse);
        // verify that user really is in repository
        User newUser = userRepository.findOne(username);
        assertNotNull(newUser);
        //check if nothing change except attributes
        assertEquals(user.getRecoveryMail(), newUser.getRecoveryMail());
        assertEquals(user.getOwnedServices().size(), newUser.getOwnedServices().size());
        assertEquals(user.getPasswordEncrypted(), newUser.getPasswordEncrypted());
        assertEquals(user.getClientCertificates().size(), newUser.getClientCertificates().size());
        assertNotEquals(user.getAttributes().size(), newUser.getAttributes().size());
        assertTrue(newUser.getAttributes().containsValue(attributeValue));
        assertTrue(newUser.getAttributes().containsKey(key));
    }

    @Test(expected = UserManagementException.class)
    public void userAttributesUpdateFailUserNotInDB() throws SecurityException {

        assertNull(userRepository.findOne(username));
        // update user who doesn't exist in db
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, ""),
                        recoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.ATTRIBUTES_UPDATE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test
    public void userDeleteSuccess() throws
            SecurityException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        // prepare the user in db including certificates
        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        Map<String, Certificate> clientCertificates = new HashMap<>();
        clientCertificates.put(clientId, new Certificate(CryptoHelper.convertX509ToPEM(userCertificate)));
        userRepository.save(
                new User(username,
                        passwordEncoder.encode(password),
                        recoveryMail,
                        clientCertificates,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashSet<>()));

        // verify that app really is in repository
        assertTrue(userRepository.exists(username));
        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // delete the user
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, ""),
                        "",
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.DELETE);
        ManagementStatus status = usersManagementService.authManage(userManagementRequest);
        assertEquals(ManagementStatus.OK, status);
        // verify that user is not anymore in the repository
        assertFalse(userRepository.exists(username));

        // verify that the user certificate was indeed revoked
        assertTrue(revokedKeysRepository.exists(username));
        SubjectsRevokedKeys revokedKeys = revokedKeysRepository.findOne(username);
        assertNotNull(revokedKeys);

        // verify that the public keys were revoke
        Set<String> certs = new HashSet<>();
        for (Certificate c : clientCertificates.values()) {
            certs.add(Base64.getEncoder().encodeToString(c.getX509().getPublicKey().getEncoded()));
        }
        assertTrue(revokedKeys.getRevokedKeysSet().containsAll(certs));
        assertEquals(certs.size(), revokedKeys.getRevokedKeysSet().size());
    }

    @Test(expected = NotExistingUserException.class)
    public void userDeleteFailMissingUsername() throws SecurityException {
        // delete the user
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(),
                        "",
                        UserRole.NULL,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.DELETE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test(expected = NotExistingUserException.class)
    public void userDeleteFailNotExistingUser() throws SecurityException {
        // verify that the user is not in the repo
        assertFalse(userRepository.exists(username));

        // delete the user
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, ""),
                        "",
                        UserRole.NULL,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.DELETE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test(expected = UserManagementException.class)
    public void userDeleteFailOwnedServicesNotEmpty() throws
            SecurityException {

        // save service owner
        User serviceOwner = createUser(username, password, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(serviceOwner);
        // save platform
        Platform platform = new Platform(platformId, "", "", serviceOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        // update service owner
        serviceOwner.getOwnedServices().add(platformId);
        userRepository.save(serviceOwner);

        // delete the user
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, ""),
                        "",
                        UserRole.NULL,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.DELETE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test
    public void userDeleteRecreateAndDeleteSuccess() throws
            SecurityException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        // prepare the user in db
        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        Map<String, Certificate> clientCertificates = new HashMap<>();
        clientCertificates.put("clientId", new Certificate(CryptoHelper.convertX509ToPEM(userCertificate)));
        userRepository.save(new User(username, passwordEncoder.encode(password), recoveryMail, clientCertificates, UserRole.USER, new HashMap<>(), new HashSet<>()));

        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // delete the user
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, password),
                        "",
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.DELETE);
        usersManagementService.authManage(userManagementRequest);
        log.debug("User successfully unregistered!");

        // verify that app is not anymore in the repository
        assertFalse(userRepository.exists(username));

        // verify that the user certificate was indeed revoked
        assertTrue(revokedKeysRepository.exists(username));
        SubjectsRevokedKeys revokedKeys = revokedKeysRepository.findOne(username);
        assertNotNull(revokedKeys);

        // verify that the public keys were revoke
        Set<String> testCertificatesSet = new HashSet<>();
        for (Certificate c : clientCertificates.values()) {
            testCertificatesSet.add(Base64.getEncoder().encodeToString(c.getX509().getPublicKey().getEncoded()));
        }
        assertTrue(revokedKeys.getRevokedKeysSet().containsAll(testCertificatesSet));

        // add user again
        userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, "NewPassword"),
                new UserDetails(
                        new Credentials(username, "NewPassword"),
                        "nullMail",
                        UserRole.SERVICE_OWNER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.CREATE);
        assertEquals(ManagementStatus.OK, usersManagementService.authManage(userManagementRequest));

        // verify that app really is in repository
        user = userRepository.findOne(username);

        // add a different cert to the repo
        user.getClientCertificates().put(
                "someId",
                new Certificate(CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-2-c1"))));
        userRepository.save(user);

        // delete user again
        userManagementRequest.setOperationType(OperationType.DELETE);
        assertEquals(ManagementStatus.OK, usersManagementService.authManage(userManagementRequest));

        // add to the test
        testCertificatesSet.add(Base64.getEncoder().encodeToString(user.getClientCertificates().get("someId").getX509().getPublicKey().getEncoded()));

        // verify that both old and new keys are revoked
        revokedKeys = revokedKeysRepository.findOne(username);
        assertTrue(revokedKeys.getRevokedKeysSet().containsAll(testCertificatesSet));

        // verify that revoked keys doesn't include a fake cert
        testCertificatesSet.add(Base64.getEncoder().encodeToString(getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1").getPublicKey().getEncoded()));
        assertFalse(revokedKeys.getRevokedKeysSet().containsAll(testCertificatesSet));
    }

    @Test
    public void userUpdateSuccess() throws SecurityException {

        // save user in db
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        // verify that user is in the repository
        assertTrue(userRepository.exists(username));
        String newPassword = "NewPassword";
        assertNotEquals(newPassword, password);
        // update user (new password)
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, password),
                new UserDetails(
                        new Credentials(username, newPassword),
                        "",
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.UPDATE);
        ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);
        assertEquals(ManagementStatus.OK, userRegistrationResponse);
        // verify that user really is in repository
        User registeredUser = userRepository.findOne(username);
        assertNotNull(registeredUser);
        // verify if password is changed
        assertTrue(passwordEncoder.matches(newPassword, registeredUser.getPasswordEncrypted()));
        // and recovery mail is still the same
        assertEquals(recoveryMail, registeredUser.getRecoveryMail());

        String newRecoveryMail = "newRecoveryMail";
        // update user (new recovery mail)
        userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, newPassword),
                new UserDetails(
                        new Credentials(username, ""),
                        newRecoveryMail,
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.UPDATE);
        userRegistrationResponse = usersManagementService.authManage(userManagementRequest);
        assertEquals(ManagementStatus.OK, userRegistrationResponse);
        // verify that user really is in repository
        registeredUser = userRepository.findOne(username);
        assertNotNull(registeredUser);
        // verify if recoveryMail is changed
        assertEquals(newRecoveryMail, registeredUser.getRecoveryMail());
        // and password is still the same
        assertTrue(passwordEncoder.matches(newPassword, registeredUser.getPasswordEncrypted()));
    }

    @Test(expected = UserManagementException.class)
    public void userUpdateFailUserNotInDB() throws SecurityException {
        assertNull(userRepository.findOne(appUsername));
        // update user who doesn't exist in db
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, password),
                new UserDetails(
                        new Credentials(username, "NewPassword"),
                        "nullMail",
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.UPDATE);
        usersManagementService.authManage(userManagementRequest);
    }

        @Test(expected = UserManagementException.class)
        public void userUpdateFailWrongAuthorizationUsername() throws SecurityException {

            // save user in db
            User user = createUser(username, password, recoveryMail, UserRole.USER);
            userRepository.save(user);
            // update user giving wrong authorization username
            UserManagementRequest userManagementRequest = new UserManagementRequest(
                    new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                    new Credentials(wrongUsername, password),
                    new UserDetails(
                            new Credentials(username, "NewPassword"),
                            "nullMail",
                            UserRole.USER,
                            new HashMap<>(),
                            new HashMap<>()),
                    OperationType.UPDATE);
            usersManagementService.authManage(userManagementRequest);
        }

    @Test(expected = UserManagementException.class)
    public void userUpdateFailWrongAuthorizationPassword() throws SecurityException {

        // save user in db
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        // update giving wrong authorization password
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, wrongPassword),
                new UserDetails(
                        new Credentials(username, "NewPassword"),
                        "nullMail",
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.UPDATE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test(expected = UserManagementException.class)
    public void userUpdateFailNoAuthorizationCredentials() throws SecurityException {

        // save user in db
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        // update giving wrong authorization password
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(),
                new UserDetails(
                        new Credentials(username, "NewPassword"),
                        "nullMail",
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.UPDATE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test(expected = UserManagementException.class)
    public void userUpdateFailUpdateOfDifferentUser() throws SecurityException {

        // save user in db
        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);
        // save user to update in db
        String differentUsername = "differentUsername";
        String differentPassword = "differentPassword";
        User differentuser = createUser(differentUsername, differentPassword, recoveryMail, UserRole.USER);
        userRepository.save(differentuser);
        // update giving wrong authorization credentials
        UserManagementRequest userManagementRequest = new UserManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(differentUsername, differentPassword),
                new UserDetails(
                        new Credentials(username, "NewPassword"),
                        "nullMail",
                        UserRole.USER,
                        new HashMap<>(),
                        new HashMap<>()),
                OperationType.UPDATE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test
    public void getUserDetailsSuccess() throws UserManagementException, AAMException, CertificateException {
        //  put user into database
        // new attributes map
        String key = "key";
        String testCertificate = "testCertificateString";
        Map<String, String> attributes = new HashMap<>();
        attributes.put(key, "attribute");
        Map<String, Certificate> certificateMap = new HashMap<>();
        certificateMap.put(key, new Certificate(testCertificate));
        Set<String> ownedServices = new HashSet<>();
        ownedServices.add("ownedService");

        User user = new User(username, password, recoveryMail, certificateMap, UserRole.SERVICE_OWNER, attributes, ownedServices);
        userRepository.save(user);
        //  Request user with matching credentials
        UserDetails userDetails = aamClient.getUserDetails(new Credentials(username, password));
        assertNotNull(userDetails);
        //check the payload
        assertEquals(user.getRecoveryMail(), userDetails.getRecoveryMail());
        assertEquals(user.getRole(), userDetails.getRole());
        assertEquals(user.getUsername(), userDetails.getCredentials().getUsername());
        assertEquals(1, userDetails.getAttributes().size());
        assertTrue(userDetails.getAttributes().containsKey(key));
        assertEquals(1, userDetails.getClients().size());
        assertTrue(userDetails.getClients().containsKey(key));
        //password of the user should not be revealed
        assertTrue(userDetails.getCredentials().getPassword().isEmpty());
    }

    @Test(expected = UserManagementException.class)
    public void getUserDetailsFailNotExistingUser() throws UserManagementException, AAMException {
        assertFalse(userRepository.exists(username));
        //  Request user that is NOT in database
        aamClient.getUserDetails(new Credentials(username, password));
    }

    @Test(expected = UserManagementException.class)
    public void getUserDetailsFailWrongPassword() throws UserManagementException, AAMException {
        //  Register user in database
        User user = createUser(username, password, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(user);
        //  Request existing user with incorrect password
        aamClient.getUserDetails(new Credentials(username, wrongPassword));
    }


}
