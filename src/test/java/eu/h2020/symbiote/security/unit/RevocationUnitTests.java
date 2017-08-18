package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.GetClientCertificateService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.*;

/**
 * Test suite for revocation (unit tests)
 *
 * @author Jakub Toczek (PSNC)
 */
@TestPropertySource("/core.properties")
public class RevocationUnitTests extends
        AbstractAAMTestSuite {

    private final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    private final String TEST_CERTIFICATE_STRING =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
                    "MIHgMIGHAgEAMCUxIzAhBgNVBAMMGmNvbXBvbmVudElkQHRlc3RQbGF0Zm9ybUlk\n" +
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEo9V8WZlyRfe4NX1dYnjFxnez1LDs\n" +
                    "qorDwMWDJU7i10U6R4yNDizqcbt55diSP1LLg/CSkq7VvI8lwjF8B+c1aaAAMAoG\n" +
                    "CCqGSM49BAMCA0gAMEUCIDStx6Ug8p26VycHzDdGnA9CFlKmiASLjupARquOPtuc\n" +
                    "AiEAv4y4ryyHNDO1opy+LZX05CYtYCfJmElEMIs1gYbLz94=\n" +
                    "-----END CERTIFICATE REQUEST-----\n";
    @Autowired
    private RevocationHelper revocationHelper;
    @Autowired
    private CertificationAuthorityHelper certificationAuthorityHelper;
    @Autowired
    private GetClientCertificateService getClientCertificateService;
    @Autowired
    private RevokedKeysRepository revokedKeysRepository;

    //TODO @JT revokeCertificates unit tests
    @Test
    public void revokeUserCertyficateUsingCommonNameSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        getClientCertificateService.getCertificate(certRequest);
        User user = userRepository.findOne(appUsername);
        assertNotNull(user.getClientCertificates().get(clientId));
        String commonName = appUsername + illegalSign + clientId;

        assertNotNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        assertNull(revokedKeysRepository.findOne(appUsername));

        revocationHelper.revokeCertificate(new Credentials(appUsername, password), null, commonName);

        assertNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        assertTrue(revokedKeysRepository.findOne(appUsername).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    @Test
    public void revokePlatformCertyficateUsingCommonNameSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, null, null);
        platformRepository.save(platform);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateString = getClientCertificateService.getCertificate(certRequest);

        platform.setPlatformAAMCertificate(new Certificate(certificateString));
        platformRepository.save(platform);

        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        platformOwner = userRepository.findOne(platformOwnerUsername);
        assertFalse(platformOwner.getOwnedPlatforms().isEmpty());
        assertFalse(platformOwner.getOwnedPlatforms().get(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        String commonName = platformId;

        assertFalse(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        assertNull(revokedKeysRepository.findOne(platformId));

        revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), null, commonName);

        assertTrue(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        assertTrue(revokedKeysRepository.findOne(platformId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    @Test
    public void revokePlatformComponentCertyficateUsingCommonNameSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, null, new HashMap<String, Certificate>());
        platformRepository.save(platform);
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateString = getClientCertificateService.getCertificate(certRequest);
        platform.getComponentCertificates().put(componentId, new Certificate(certificateString));
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);
        //generate component certificate

        String commonName = componentId + illegalSign + platformId;

        assertNotNull(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getComponentCertificates().get(componentId));
        assertNull(revokedKeysRepository.findOne(platformId));

        revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), null, commonName);

        assertNull(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getComponentCertificates().get(componentId));
        assertTrue(revokedKeysRepository.findOne(platformId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    @Test
    public void revokeFailsUsingWrongCredentials() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = getClientCertificateService.getCertificate(certRequest);
        User user = userRepository.findOne(appUsername);
        assertNotNull(user.getClientCertificates().get(clientId));
        String commonName = appUsername + illegalSign + clientId;
        try {
            revocationHelper.revokeCertificate(new Credentials(wrongusername, password), null, commonName);
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(NotExistingUserException.class, e.getClass());
        }
        try {
            revocationHelper.revokeCertificate(new Credentials(appUsername, wrongpassword), null, commonName);
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(WrongCredentialsException.class, e.getClass());
        }
    }

    @Test
    public void revokeCertificateFailsUsingWrongCommonNameAsUser() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = getClientCertificateService.getCertificate(certRequest);
        User user = userRepository.findOne(appUsername);
        assertNotNull(user.getClientCertificates().get(clientId));
        String commonName = wrongusername + illegalSign + clientId;
        try {
            revocationHelper.revokeCertificate(new Credentials(appUsername, password), null, commonName);
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(SecurityException.class, e.getClass());
        }
        commonName = appUsername + illegalSign + wrongClientId;
        try {
            revocationHelper.revokeCertificate(new Credentials(appUsername, password), null, commonName);
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(WrongCredentialsException.class, e.getClass());
        }
        commonName = clientId;
        try {
            revocationHelper.revokeCertificate(new Credentials(appUsername, password), null, commonName);
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(SecurityException.class, e.getClass());
        }
    }

    @Test
    public void revokeCertificateFailsUsingWrongCommonNameAsPlatformOwner() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        User platformOwner = savePlatformOwner();
        String commonName = platformId;
        try {
            revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), null, commonName);
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(WrongCredentialsException.class, e.getClass());
        }
        commonName = componentId + illegalSign + platformId;
        try {
            revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), null, commonName);
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(WrongCredentialsException.class, e.getClass());
        }
        Platform platform = new Platform(platformId, null, null, platformOwner, null, new HashMap<String, Certificate>());
        platformRepository.save(platform);
        try {
            revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), null, commonName);
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(WrongCredentialsException.class, e.getClass());
        }
    }

    @Test
    public void revokeCertificateFailsUsingWrongCommonName() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        saveUser();
        String commonName = clientId + illegalSign + username + illegalSign + platformId;
        try {
            revocationHelper.revokeCertificate(new Credentials(appUsername, password), null, commonName);
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(WrongCredentialsException.class, e.getClass());
        }
    }

    @Test
    public void revokeUserCertyficateUsingCertificateSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {

        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = getClientCertificateService.getCertificate(certRequest);

        assertNotNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        assertNull(revokedKeysRepository.findOne(appUsername));

        revocationHelper.revokeCertificate(new Credentials(appUsername, password), new Certificate(certificate), "");

        assertNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        assertTrue(revokedKeysRepository.findOne(appUsername).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    @Test
    public void revokePlatformCertyficateUsingCertificateSuccess() throws WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException {
        User platformOwner = savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        Platform platform = new Platform(platformId, null, null, platformOwner, null, null);
        platformRepository.save(platform);
        //create platform certificate
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = getClientCertificateService.getCertificate(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(certificate));
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        assertFalse(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        assertNull(revokedKeysRepository.findOne(platformId));

        revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), new Certificate(certificate), "");

        assertTrue(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        assertTrue(revokedKeysRepository.findOne(platformId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    @Test
    public void revokePlatformComponentCertyficateUsingCertificateSuccess() throws WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException {
        User platformOwner = savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        Platform platform = new Platform(platformId, null, null, platformOwner, null, new HashMap<String, Certificate>());
        platformRepository.save(platform);
        //create platform certificate
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = getClientCertificateService.getCertificate(certRequest);
        platform.getComponentCertificates().put(componentId, new Certificate(certificate));
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        assertNotNull(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getComponentCertificates().get(componentId));
        assertNull(revokedKeysRepository.findOne(platformId));

        revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), new Certificate(certificate), "");

        assertNull(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getComponentCertificates().get(componentId));
        assertTrue(revokedKeysRepository.findOne(platformId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }


    @Test
    public void revokeUserCertyficateUsingCertificateFailWrongCertificate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificateString = getClientCertificateService.getCertificate(certRequest);

        User user = userRepository.findOne(appUsername);
        user.getClientCertificates().remove(clientId);
        userRepository.save(user);

        try {
            revocationHelper.revokeCertificate(new Credentials(appUsername, password), new Certificate(certificateString), "");
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(CertificateException.class, e.getClass());
        }
        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), wrongusername, clientId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        certificateString = getClientCertificateService.getCertificate(certRequest);
        try {
            revocationHelper.revokeCertificate(new Credentials(appUsername, password), new Certificate(certificateString), "");
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(SecurityException.class, e.getClass());
        }
    }

    @Test
    public void revokePlatformCertyficateUsingCertificateFailNoPlatformOrWrongRole() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, null, null);
        platformRepository.save(platform);
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateString = getClientCertificateService.getCertificate(certRequest);
        try {
            revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), new Certificate(certificateString), "");
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(CertificateException.class, e.getClass());
        }
        platformOwner.setRole(UserRole.USER);
        userRepository.save(platformOwner);
        try {
            revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), new Certificate(certificateString), "");
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(SecurityException.class, e.getClass());
        }

    }
}