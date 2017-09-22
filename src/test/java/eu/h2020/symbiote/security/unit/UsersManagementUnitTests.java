package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
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
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.*;

/**
 * TODO @Maks cover user update and create scenarios better
 */
@TestPropertySource("/core.properties")
public class UsersManagementUnitTests extends AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(UsersManagementUnitTests.class);
    private final String recoveryMail = "null@dev.null";

    @Test
    public void userInternalCreateSuccess() throws SecurityException {
        String appUsername = "NewApplication";

        // verify that app is not in the repository
        User registeredUser = userRepository.findOne(appUsername);
        assertNull(registeredUser);
        // new attributes map
        Map<String, String> attributes = new HashMap<>();
        attributes.put("key", "attribute");

        // manage new user to db
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(appUsername, "NewPassword"),
                new UserDetails(new Credentials(appUsername, "NewPassword"), "nullId", "nullMail", UserRole.USER, attributes, new HashMap<>())
                , OperationType.CREATE);
        ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);

        // verify that app really is in repository
        registeredUser = userRepository.findOne(appUsername);
        assertNotNull(registeredUser);
        assertEquals(UserRole.USER, registeredUser.getRole());
        assertEquals(1, registeredUser.getAttributes().size());
        assertEquals(userRegistrationResponse, ManagementStatus.OK);
    }


    @Test
    public void userInternalCreateFailForAAMAdminRegistrationAttempt() throws SecurityException {
        // manage new user to db
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(appUsername, "NewPassword"),
                new UserDetails(new Credentials(AAMOwnerUsername, "NewPassword"), "nullId", "nullMail", UserRole.USER, new HashMap<>(), new HashMap<>())
                , OperationType.CREATE);
        ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);

        // verify that we got an error
        assertEquals(userRegistrationResponse, ManagementStatus.ERROR);
    }

    @Test
    public void userInternalCreateFailForGuestAttempt() throws SecurityException {
        // managePlatform new user to db
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(appUsername, "NewPassword"),
                new UserDetails(new Credentials(SecurityConstants.GUEST_NAME, "NewPassword"), "nullId", "nullMail", UserRole.USER, new HashMap<>(), new HashMap<>())
                , OperationType.CREATE);
        ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);

        // verify that we got an error
        assertEquals(userRegistrationResponse, ManagementStatus.ERROR);
    }

    @Test
    public void userInternalAttributesUpdateSuccess() throws SecurityException {
        User user = saveUser();
        assertEquals(0, user.getAttributes().size());
        Map<String, String> attributes = new HashMap<>();
        attributes.put("key", "attribute");
        // update attributes - new values of mail and federatedId to check, if they change too
        //wrong password used to check, if it is checked (should not be)
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(appUsername, password),
                new UserDetails(new Credentials(appUsername, wrongPassword), "newId", "newMail", UserRole.USER, attributes, new HashMap<>())
                , OperationType.ATTRIBUTES_UPDATE);
        ManagementStatus userRegistrationResponse = usersManagementService.authManage(userManagementRequest);
        assertEquals(userRegistrationResponse, ManagementStatus.OK);
        // verify that app really is in repository
        User newUser = userRepository.findOne(appUsername);
        assertNotNull(newUser);
        //check if nothing change except attributes
        assertEquals(user.getRecoveryMail(), newUser.getRecoveryMail());
        assertEquals(user.getOwnedPlatforms().size(), newUser.getOwnedPlatforms().size());
        assertEquals(user.getPasswordEncrypted(), newUser.getPasswordEncrypted());
        assertEquals(user.getClientCertificates().size(), newUser.getClientCertificates().size());
        assertNotEquals(user.getAttributes().size(), newUser.getAttributes().size());
        assertTrue(newUser.getAttributes().containsValue("attribute"));
        assertTrue(newUser.getAttributes().containsKey("key"));

    }

    @Test
    public void userInternalCreateFailForPORegistrationAttemptInPlatformAAM() throws SecurityException {
        String appUsername = "NewApplication";

        // verify that app is not in the repository
        User registeredUser = userRepository.findOne(appUsername);
        assertNull(registeredUser);

        // manage new user to db
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(appUsername, "NewPassword"),
                new UserDetails(new Credentials(appUsername, "NewPassword"), "nullId", "nullMail", UserRole.PLATFORM_OWNER, new HashMap<>(), new HashMap<>()),
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

    @Test
    public void userInternalDeleteSuccess() throws
            SecurityException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        // prepare the user in db
        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        Map<String, Certificate> clientCertificates = new HashMap<>();
        clientCertificates.put("clientId", new Certificate(CryptoHelper.convertX509ToPEM(userCertificate)));
        userRepository.save(new User(username, passwordEncoder.encode(password), recoveryMail, clientCertificates, UserRole.USER, new HashMap<>(), new HashSet<>()));

        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // delete the user
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(),
                new UserDetails(new Credentials(username, password), "", "", UserRole.NULL, new HashMap<>(), new HashMap<>()),
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
        Set<String> certs = new HashSet<>();
        for (Certificate c : clientCertificates.values()) {
            certs.add(Base64.getEncoder().encodeToString(c.getX509().getPublicKey().getEncoded()));
        }
        assertTrue(revokedKeys.getRevokedKeysSet().containsAll(certs));

        // verify that revoked keys doesn't include a fake cert
        certs.add(Base64.getEncoder().encodeToString(getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1").getPublicKey().getEncoded()));
        assertFalse(revokedKeys.getRevokedKeysSet().containsAll(certs));
    }


    @Test
    public void userInternalDeleteRecreateAndDeleteSuccess() throws
            SecurityException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        // prepare the user in db
        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        Map<String, Certificate> clientCertificates = new HashMap<>();
        clientCertificates.put("clientId", new Certificate(CryptoHelper.convertX509ToPEM(userCertificate)));
        userRepository.save(new User(username, passwordEncoder.encode(password), recoveryMail, clientCertificates, UserRole.USER, new HashMap<>(), new HashSet<>()));

        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // delete the user
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(),
                new UserDetails(new Credentials(username, password), "", "", UserRole.USER, new HashMap<>(), new HashMap<>()),
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
        userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, "NewPassword"),
                new UserDetails(new Credentials(username, "NewPassword"), "nullId", "nullMail", UserRole.PLATFORM_OWNER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE);
        assertEquals(ManagementStatus.OK, usersManagementService.authManage(userManagementRequest));

        // verify that app really is in repository
        user = userRepository.findOne(username);

        // add a different cert to the repo
        user.getClientCertificates().put(
                "someId",
                new Certificate(CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore("platform_1.p12", "platform-1-2-c1"))));
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
        testCertificatesSet.add(Base64.getEncoder().encodeToString(getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1").getPublicKey().getEncoded()));
        assertFalse(revokedKeys.getRevokedKeysSet().containsAll(testCertificatesSet));
    }

    @Test(expected = InvalidArgumentsException.class)
    public void userInternalDeleteFailMissingUsername() throws SecurityException {
        // delete the user
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(),
                new UserDetails(new Credentials("", password), "", "", UserRole.NULL, new HashMap<>(), new HashMap<>()),
                OperationType.DELETE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test(expected = NotExistingUserException.class)
    public void userInternalDeleteFailNotExistingUser() throws SecurityException {
        // verify that the user is not in the repo
        assertFalse(userRepository.exists(username));

        // delete the user
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(),
                new UserDetails(new Credentials(username, password), "", "", UserRole.NULL, new HashMap<>(), new HashMap<>()),
                OperationType.DELETE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test(expected = UserManagementException.class)
    public void userInternalDeleteFailForOwnedPlatformsNotEmpty() throws
            SecurityException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        // save PO
        User platformOwner = new User(username, passwordEncoder.encode(password), recoveryMail, new HashMap<>(), UserRole.PLATFORM_OWNER, new HashMap<>(), new HashSet<>());
        userRepository.save(platformOwner);

        // save platform
        Platform platform = new Platform(platformId, "", "", platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);

        // update platform owner
        platformOwner.getOwnedPlatforms().add(platformId);
        userRepository.save(platformOwner);

        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // delete the user
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(),
                new UserDetails(new Credentials(username, ""), "", "", UserRole.NULL, new HashMap<>(), new HashMap<>()),
                OperationType.DELETE);
        usersManagementService.authManage(userManagementRequest);
    }

    private X509Certificate getCertificateFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void userCreateFailInvalidArguments() throws SecurityException {

        // attempt adding new user to database using invalid request
        UserManagementRequest userManagementRequest = new UserManagementRequest(null,
                new Credentials(appUsername, "NewPassword"),
                new UserDetails(new Credentials(appUsername, "NewPassword"), "nullId", "nullMail", UserRole.USER, new HashMap<>(), new HashMap<>()),
                OperationType.CREATE);
        usersManagementService.authManage(userManagementRequest);

    }

    @Test(expected = InvalidArgumentsException.class)
    public void userCreateFailIncorrectUsernameFormat() throws SecurityException {
        String incorrectName = "@#$%^";

        // manage new user to db
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(incorrectName, "NewPassword"),
                new UserDetails(new Credentials(incorrectName, "NewPassword"), "nullId", "nullMail", UserRole.USER, new HashMap<>(), new HashMap<>())
                , OperationType.CREATE);
        usersManagementService.authManage(userManagementRequest);
    }

    @Test
    public void getExistingUserOverRestSuccess() throws UserManagementException {
        //  Register user in database
        User platformOwner = new User(username, passwordEncoder.encode(password), recoveryMail, new HashMap<>(), UserRole.PLATFORM_OWNER, new HashMap<>(), new HashSet<>());
        userRepository.save(platformOwner);
        //  Request user with matching credentials
        UserDetails userDetails = aamClient.getUserDetails(new Credentials(username, password));
        assertNotNull(userDetails);
    }

    @Test(expected = UserManagementException.class)
    public void getNotExistingUserOverRestFailure() throws UserManagementException {
        //  Register user in database
        User platformOwner = new User(username, passwordEncoder.encode(password), recoveryMail, new HashMap<>(), UserRole.PLATFORM_OWNER, new HashMap<>(), new HashSet<>());
        userRepository.save(platformOwner);
        //  Request different user that is NOT in database
        aamClient.getUserDetails(new Credentials("NotExisting", "somePassword"));
    }

    @Test(expected = UserManagementException.class)
    public void getUserOverRestFailsForwrongPassword() throws UserManagementException {
        //  Register user in database
        User platformOwner = new User(username, passwordEncoder.encode(password), recoveryMail, new HashMap<>(), UserRole.PLATFORM_OWNER, new HashMap<>(), new HashSet<>());
        userRepository.save(platformOwner);
        //  Request existing user with incorrect password
        aamClient.getUserDetails(new Credentials(username, "WrongPassword"));
    }
}
