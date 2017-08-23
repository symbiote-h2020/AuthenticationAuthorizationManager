package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.GetClientCertificateService;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM2;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.concurrent.TimeoutException;

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
    @Autowired
    private TokenIssuer tokenIssuer;
    @Autowired
    private GetTokenService getTokenService;

    @Bean
    DummyPlatformAAM dummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

    @Bean
    DummyPlatformAAM2 dummyPlatformAAM2() {
        return new DummyPlatformAAM2();
    }

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
        Platform platform = new Platform(platformId, null, null, platformOwner, null, new HashMap<>());
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

        assertFalse(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        assertNull(revokedKeysRepository.findOne(platformId));

        revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), null, platformId);

        assertTrue(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        assertTrue(revokedKeysRepository.findOne(platformId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    @Test
    public void revokePlatformComponentCertyficateUsingCommonNameSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, null, new HashMap<>());
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
        Platform platform = new Platform(platformId, null, null, platformOwner, null, new HashMap<>());
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
        //revoke certificate using revoked certificate
        //check if there is user certificate in database
        assertNotNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        //check if there is revoked key for user
        assertNull(revokedKeysRepository.findOne(appUsername));
        //check if revocation ended with success using certificate
        assertTrue(revocationHelper.revokeCertificate(new Credentials(appUsername, password), new Certificate(certificate), ""));
        //check if there is not user certificate in database
        assertNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        //check if there is revoked key for user
        assertTrue(revokedKeysRepository.findOne(appUsername).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));

        pair = CryptoHelper.createKeyPair();
        assertFalse(revokedKeysRepository.findOne(appUsername).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
        csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificateNew = getClientCertificateService.getCertificate(certRequest);
        //revoke certificate using revoked certificate
        //check if there is user certificate in database
        assertNotNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        //check if revocation ended with success using certificate with revoked key
        assertTrue(revocationHelper.revokeCertificate(new Credentials(appUsername, password), new Certificate(certificate), ""));


    }

    @Test
    public void revokePlatformCertyficateUsingCertificateSuccess() throws WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException {
        User platformOwner = savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        Platform platform = new Platform(platformId, null, null, platformOwner, null, new HashMap<>());
        platformRepository.save(platform);
        //create platform certificate
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = getClientCertificateService.getCertificate(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(certificate));
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);
        //revoke platform certificate
        //check if there is platform certificate in database
        assertFalse(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        //check if there is any revoked key for platformId
        assertNull(revokedKeysRepository.findOne(platformId));
        //check if revocation ended with success
        assertTrue(revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), new Certificate(certificate), ""));
        //check if there isn't platform certificate in database
        assertTrue(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        //check if there is revoked key for platformId
        assertTrue(revokedKeysRepository.findOne(platformId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));

        //create new certificate for platform
        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateNew = getClientCertificateService.getCertificate(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(certificateNew));
        platformRepository.save(platform);

        //revoke certificate using revoked certificate
        //check if there is platform certificate in database
        assertFalse(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        //check if revocation ended with success using certificate with revoked key
        assertTrue(revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), new Certificate(certificate), ""));
    }

    @Test(expected = WrongCredentialsException.class)
    public void revokePlatformCertyficateUsingCertificateFailWrongCertificate() throws WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException {
        User platformOwner = savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        Platform platform = new Platform(platformId, null, null, platformOwner, null, new HashMap<>());
        platformRepository.save(platform);
        //create platform certificate
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = getClientCertificateService.getCertificate(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(certificate));
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        //create new certificate for platform
        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateNew = getClientCertificateService.getCertificate(certRequest);

        //revoke certificate using revoked certificate
        //check if there is platform certificate in database
        assertFalse(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        //check if revocation ended with success using certificate with revoked key
        revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), new Certificate(certificateNew), "");
    }

    @Test
    public void revokePlatformComponentCertyficateUsingCertificateSuccess() throws WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException {
        User platformOwner = savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        Platform platform = new Platform(platformId, null, null, platformOwner, null, new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);
        //create platform certificate
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = getClientCertificateService.getCertificate(certRequest);
        platform.getComponentCertificates().put(componentId, new Certificate(certificate));
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);
        //revoke platform certificate
        //check if there is component certificate in platform database
        assertNotNull(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getComponentCertificates().get(componentId));
        //check if there is any revoked key for platformId
        assertNull(revokedKeysRepository.findOne(platformId));
        //check if revocation ended with success
        assertTrue(revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), new Certificate(certificate), ""));
        //check if there isn't component certificate in platform database
        assertNull(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getComponentCertificates().get(componentId));
        //check if there is revoked key for platformId
        assertTrue(revokedKeysRepository.findOne(platformId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));

        //create new certificate for platform
        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateNew = getClientCertificateService.getCertificate(certRequest);
        platform.getComponentCertificates().put(componentId, new Certificate(certificateNew));
        platformRepository.save(platform);

        //revoke certificate using revoked certificate
        //check if there is component certificate in database
        assertNotNull(userRepository.findOne(platformOwnerUsername).getOwnedPlatforms().get(platformId).getComponentCertificates().get(componentId));
        //check if revocation ended with success using certificate with revoked key
        assertTrue(revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), new Certificate(certificate), ""));

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
            assertEquals(WrongCredentialsException.class, e.getClass());
        }
    }

    @Test
    public void revokePlatformCertyficateUsingCertificateFailNoPlatformOrWrongRole() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, null, new HashMap<>());
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
            assertEquals(WrongCredentialsException.class, e.getClass());
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

    @Test
    public void revokeCertificateUsingCertificateFailEmptyCertificateSent() {
        savePlatformOwner();
        try {
            revocationHelper.revokeCertificate(new Credentials(platformOwnerUsername, platformOwnerPassword), new Certificate(), "");
            fail("No exception detected");
        } catch (Exception e) {
            assertEquals(CertificateException.class, e.getClass());
        }
    }

    @Test
    public void revokeHomeToken() throws SecurityException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, UnrecoverableKeyException, OperatorCreationException, JWTCreationException, WrongCredentialsException, NotExistingUserException, ValidationException {
        addTestUserWithClientCertificateToRepository();

        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId);

        // verify the user token is not yet revoked
        assertFalse(revokedTokensRepository.exists(homeToken.getClaims().getId()));
        // revocation
        revocationHelper.revokeHomeToken(new Credentials(username, password), homeToken);

        // verify the user token is revoked
        assertTrue(revokedTokensRepository.exists(homeToken.getClaims().getId()));
    }

    @Test
    public void revokeHomeTokenByPlatformSuccess() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, WrongCredentialsException, NotExistingUserException, InvalidKeyException, OperatorCreationException, UnrecoverableKeyException, JWTCreationException, InvalidAlgorithmParameterException, InvalidArgumentsException, PlatformManagementException, UserManagementException, MalformedJWTException, ClassNotFoundException {    // issuing dummy platform token
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        KeyPair pair2 = CryptoHelper.createKeyPair();
        DummyPlatformAAM dummyPlatformAAM = dummyPlatformAAM();
        platform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAM.getRootCertificate()));
        platformRepository.save(platform);

        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, clientId, new Certificate(), pair2.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));
        // ensure that token is not in revoked token repository
        assertFalse(revokedTokensRepository.exists(dummyHomeToken.getClaims().getId()));
        revocationHelper.revokeHomeToken(new Credentials(platformOwnerUsername, platformOwnerPassword), dummyHomeToken);
        assertTrue(revokedTokensRepository.exists(dummyHomeToken.getClaims().getId()));
    }

    @Test(expected = ValidationException.class)
    public void revokeHomeTokenByPlatformFailNoRightsToToken() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, WrongCredentialsException, NotExistingUserException, InvalidKeyException, OperatorCreationException, UnrecoverableKeyException, JWTCreationException, InvalidAlgorithmParameterException, InvalidArgumentsException, PlatformManagementException, UserManagementException, MalformedJWTException, ClassNotFoundException {    // issuing dummy platform token
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, csrString);
        String certificateString = getClientCertificateService.getCertificate(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(certificateString));
        platformRepository.save(platform);

        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, platformId, new Certificate(), pair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        ResponseEntity<?> loginResponse = dummyPlatformAAM().getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // ensure that token is not in revoked token repository
        assertFalse(revokedTokensRepository.exists(dummyHomeToken.getClaims().getId()));
        // revocation
        revocationHelper.revokeHomeToken(new Credentials(platformOwnerUsername, platformOwnerPassword), dummyHomeToken);
    }

    @Test(expected = ValidationException.class)
    public void revokeHomeTokeFailWrongToken() throws CertificateException, WrongCredentialsException, NotExistingUserException, ValidationException {
        revocationHelper.revokeHomeToken(new Credentials(platformOwnerUsername, wrongpassword), new Token());
    }

    @Test(expected = WrongCredentialsException.class)
    public void revokeHomeTokeFailWrongCredentials() throws CertificateException, WrongCredentialsException, NotExistingUserException, ValidationException, JWTCreationException {
        savePlatformOwner();
        revocationHelper.revokeHomeToken(new Credentials(platformOwnerUsername, wrongpassword), tokenIssuer.getGuestToken());
    }

    @Test(expected = NotExistingUserException.class)
    public void revokeHomeTokeFailWrongUser() throws CertificateException, WrongCredentialsException, NotExistingUserException, ValidationException, JWTCreationException {
        revocationHelper.revokeHomeToken(new Credentials(platformOwnerUsername, wrongpassword), tokenIssuer.getGuestToken());
    }

    @Test
    public void revokeForeignTokenSuccess() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException, IOException, TimeoutException, JWTCreationException, ValidationException, NotExistingUserException, InvalidArgumentsException, WrongCredentialsException, MalformedJWTException, ClassNotFoundException {
        addTestUserWithClientCertificateToRepository();
        assertNotNull(userRepository.findOne(username));
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        DummyPlatformAAM dummyPlatformAAM = dummyPlatformAAM();
        Token token = new Token(dummyPlatformAAM.getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        assertNotNull(token);

        User platformOwner = savePlatformOwner();
        String platformId = "platform-1";
        Platform platform = new Platform(platformId, serverAddress + "/test", null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        Platform dummyPlatform = platformRepository.findOne(platformId);
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAM.getRootCertificate()));
        platformRepository.save(dummyPlatform);

        // adding a dummy foreign rule
        tokenIssuer.foreignMappingRules.put("DummyRule", "dummyRule");
        Token foreignToken = getTokenService.getForeignToken(token, "", "");
        assertNotNull(foreignToken);

        assertFalse(revokedTokensRepository.exists(foreignToken.getClaims().getId()));
        assertTrue(revocationHelper.revokeForeignToken(token, foreignToken));
        assertTrue(revokedTokensRepository.exists(foreignToken.getClaims().getId()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void revokeForeignTokenFailWrongHomeTokenWrongSubject() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException, IOException, TimeoutException, JWTCreationException, ValidationException, NotExistingUserException, InvalidArgumentsException, WrongCredentialsException, MalformedJWTException, ClassNotFoundException {
        addTestUserWithClientCertificateToRepository();
        assertNotNull(userRepository.findOne(username));
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        DummyPlatformAAM dummyPlatformAAM = dummyPlatformAAM();
        Token token = new Token(dummyPlatformAAM.getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        assertNotNull(token);

        User platformOwner = savePlatformOwner();
        String platformId = "platform-1";
        Platform platform = new Platform(platformId, serverAddress + "/test", null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        Platform dummyPlatform = platformRepository.findOne(platformId);
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAM.getRootCertificate()));
        platformRepository.save(dummyPlatform);

        // adding a dummy foreign rule
        tokenIssuer.foreignMappingRules.put("DummyRule", "dummyRule");
        Token foreignToken = getTokenService.getForeignToken(token, "", "");
        assertNotNull(foreignToken);

        homeCredentials = new HomeCredentials(null, platformOwnerUsername, clientId, null, userKeyPair.getPrivate());
        loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        token = new Token(dummyPlatformAAM.getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));


        assertFalse(revokedTokensRepository.exists(foreignToken.getClaims().getId()));
        revocationHelper.revokeForeignToken(token, foreignToken);
    }
}