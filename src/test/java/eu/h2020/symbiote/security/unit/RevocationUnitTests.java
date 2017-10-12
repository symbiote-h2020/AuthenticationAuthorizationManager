package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.RevocationService;
import eu.h2020.symbiote.security.services.SignCertificateRequestService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
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

    @Autowired
    private RevocationService revocationService;
    @Autowired
    private CertificationAuthorityHelper certificationAuthorityHelper;
    @Autowired
    private SignCertificateRequestService signCertificateRequestService;
    @Autowired
    private ComponentCertificatesRepository componentCertificatesRepository;
    @Autowired
    private RevokedKeysRepository revokedKeysRepository;
    @Autowired
    private TokenIssuer tokenIssuer;
    @Autowired
    private GetTokenService getTokenService;
    @Autowired
    DummyPlatformAAM dummyPlatformAAM;

    //TODO @JT revokeCertificates unit tests
    @Test
    public void revokeUserCertificateUsingCommonNameSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            WrongCredentialsException,
            UserManagementException,
            ValidationException,
            PlatformManagementException,
            InvalidArgumentsException,
            NotExistingUserException {
        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        signCertificateRequestService.signCertificate(certRequest);
        User user = userRepository.findOne(appUsername);
        assertNotNull(user.getClientCertificates().get(clientId));
        String commonName = appUsername + illegalSign + clientId;
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(appUsername, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificateCommonName(commonName);

        assertNotNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        assertNull(revokedKeysRepository.findOne(appUsername));

        assertTrue(revocationService.revoke(revocationRequest).isRevoked());

        assertNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        assertTrue(revokedKeysRepository.findOne(appUsername).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    @Test
    public void revokePlatformCertificateUsingCommonNameSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            WrongCredentialsException,
            UserManagementException,
            ValidationException,
            PlatformManagementException,
            InvalidArgumentsException,
            NotExistingUserException {
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateString = signCertificateRequestService.signCertificate(certRequest);

        platform.setPlatformAAMCertificate(new Certificate(certificateString));
        platformRepository.save(platform);

        platformOwner.getOwnedPlatforms().add(platformId);
        userRepository.save(platformOwner);

        platformOwner = userRepository.findOne(platformOwnerUsername);
        assertFalse(platformOwner.getOwnedPlatforms().isEmpty());
        assertFalse(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());

        assertFalse(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        assertNull(revokedKeysRepository.findOne(platformId));

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, platformOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificateCommonName(platformId);

        assertTrue(revocationService.revoke(revocationRequest).isRevoked());

        assertTrue(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        assertTrue(revokedKeysRepository.findOne(platformId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    @Test
    public void revokeFailsUsingWrongCredentials() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificate(certRequest);
        User user = userRepository.findOne(appUsername);
        assertNotNull(user.getClientCertificates().get(clientId));
        String commonName = appUsername + illegalSign + clientId;

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificateCommonName(commonName);
        revocationRequest.setCredentials(new Credentials(wrongUsername, password));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());

        revocationRequest.setCredentials(new Credentials(appUsername, wrongPassword));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeCertificateFailsUsingWrongCommonNameAsUser() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificate(certRequest);
        User user = userRepository.findOne(appUsername);
        assertNotNull(user.getClientCertificates().get(clientId));
        String commonName = wrongUsername + illegalSign + clientId;

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificateCommonName(commonName);
        revocationRequest.setCredentials(new Credentials(appUsername, password));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());

        commonName = appUsername + illegalSign + wrongClientId;
        revocationRequest.setCertificateCommonName(commonName);
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());

        commonName = clientId;
        revocationRequest.setCertificateCommonName(commonName);
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeCertificateFailsUsingWrongCommonNameAsPlatformOwner() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        User platformOwner = savePlatformOwner();
        String commonName = platformId;

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificateCommonName(commonName);
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, platformOwnerPassword));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());

        commonName = componentId + illegalSign + platformId;

        revocationRequest.setCertificateCommonName(commonName);
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());

        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);

        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeCertificateFailsUsingWrongCommonName() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        saveUser();
        String commonName = clientId + illegalSign + username + illegalSign + platformId;

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificateCommonName(commonName);
        revocationRequest.setCredentials(new Credentials(appUsername, password));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeUserCertificateUsingCertificateSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            WrongCredentialsException,
            UserManagementException,
            ValidationException,
            PlatformManagementException,
            InvalidArgumentsException,
            NotExistingUserException {

        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificate(certRequest);
        //revoke certificate using revoked certificate
        //check if there is user certificate in database
        assertNotNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        //check if there is revoked key for user
        assertNull(revokedKeysRepository.findOne(appUsername));
        //check if revocation ended with success using certificate
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(certificate);
        revocationRequest.setCredentials(new Credentials(appUsername, password));
        assertTrue(revocationService.revoke(revocationRequest).isRevoked());
        //check if there is not user certificate in database
        assertNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        //check if there is revoked key for user
        assertTrue(revokedKeysRepository.findOne(appUsername).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));

        pair = CryptoHelper.createKeyPair();
        assertFalse(revokedKeysRepository.findOne(appUsername).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
        csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificateNew = signCertificateRequestService.signCertificate(certRequest);
        //revoke certificate using revoked certificate
        //check if there is user certificate in database
        assertNotNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        //check if revocation ended with success using certificate with revoked key

        assertTrue(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokePlatformCertificateUsingCertificateSuccess() throws
            WrongCredentialsException,
            UserManagementException,
            ValidationException,
            PlatformManagementException,
            InvalidArgumentsException,
            NotExistingUserException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            CertificateException {
        User platformOwner = savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        //create platform certificate
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificate(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(certificate));
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().add(platformId);
        userRepository.save(platformOwner);
        //revoke platform certificate
        //check if there is platform certificate in database
        assertFalse(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        //check if there is any revoked key for platformId
        assertNull(revokedKeysRepository.findOne(platformId));
        //check if revocation ended with success
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(certificate);
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, platformOwnerPassword));
        assertTrue(revocationService.revoke(revocationRequest).isRevoked());
        //check if there isn't platform certificate in database
        assertTrue(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        //check if there is revoked key for platformId
        assertTrue(revokedKeysRepository.findOne(platformId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));

        //create new certificate for platform
        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateNew = signCertificateRequestService.signCertificate(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(certificateNew));
        platformRepository.save(platform);

        //revoke certificate using revoked certificate
        //check if there is platform certificate in database
        assertFalse(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        //check if revocation ended with success using certificate with revoked key
        assertTrue(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokePlatformCertificateUsingCertificateFailWrongCertificate() throws
            WrongCredentialsException,
            UserManagementException,
            ValidationException,
            PlatformManagementException,
            InvalidArgumentsException,
            NotExistingUserException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            CertificateException {
        User platformOwner = savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        //create platform certificate
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificate(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(certificate));
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().add(platformId);
        userRepository.save(platformOwner);

        //create new certificate for platform
        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);

        String certFromCSR = signCertificateRequestService.signCertificate(certRequest);
        //revoke certificate using revoked certificate
        //check if there is platform certificate in database
        assertFalse(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        //check if revocation ended with success using certificate with revoked key

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificatePEMString(certFromCSR);
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, platformOwnerPassword));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeUserCertificateUsingCertificateFailWrongCertificate() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            WrongCredentialsException,
            UserManagementException,
            ValidationException,
            PlatformManagementException,
            InvalidArgumentsException,
            NotExistingUserException {
        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificateString = signCertificateRequestService.signCertificate(certRequest);

        User user = userRepository.findOne(appUsername);
        user.getClientCertificates().remove(clientId);
        userRepository.save(user);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(certificateString);
        revocationRequest.setCredentials(new Credentials(appUsername, password));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());

        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), wrongUsername, clientId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        certificateString = signCertificateRequestService.signCertificate(certRequest);
        revocationRequest.setCertificatePEMString(certificateString);
        revocationRequest.setCredentials(new Credentials(appUsername, password));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokePlatformCertificateUsingCertificateFailNoPlatformOrWrongRole() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            WrongCredentialsException,
            UserManagementException,
            ValidationException,
            PlatformManagementException,
            InvalidArgumentsException,
            NotExistingUserException {
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateString = signCertificateRequestService.signCertificate(certRequest);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(certificateString);
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, platformOwnerPassword));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());

        platformOwner.setRole(UserRole.USER);
        userRepository.save(platformOwner);
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());

    }

    @Test
    public void revokeCertificateUsingCertificateFailEmptyCertificateSent() {
        savePlatformOwner();
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString("");
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, platformOwnerPassword));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeHomeTokenSuccess() throws SecurityException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, UnrecoverableKeyException, OperatorCreationException, JWTCreationException, WrongCredentialsException, NotExistingUserException, ValidationException {
        addTestUserWithClientCertificateToRepository();

        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());

        // verify the user token is not yet revoked
        assertFalse(revokedTokensRepository.exists(homeToken.getClaims().getId()));
        // revocation
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setHomeTokenString(homeToken.toString());
        revocationRequest.setCredentials(new Credentials(username, password));
        assertTrue(revocationService.revoke(revocationRequest).isRevoked());

        // verify the user token is revoked
        assertTrue(revokedTokensRepository.exists(homeToken.getClaims().getId()));
    }

    @Test
    public void revokeUserCertificateUsingCertificateByAdminSuccess() throws SecurityException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, UnrecoverableKeyException, OperatorCreationException, JWTCreationException, WrongCredentialsException, NotExistingUserException, ValidationException, InvalidAlgorithmParameterException, InvalidArgumentsException, PlatformManagementException, UserManagementException {
        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);

        assertNotNull(csrString);

        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String clientCertificate = signCertificateRequestService.signCertificate(certRequest);

        assertNotNull(clientCertificate);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificatePEMString(clientCertificate);

        assertFalse(revokedKeysRepository.exists(appUsername));
        RevocationResponse revocationResponse = revocationService.revoke(revocationRequest);

        assertTrue(revocationResponse.isRevoked());
        assertEquals(HttpStatus.OK, revocationResponse.getStatus());
        assertTrue(revokedKeysRepository.exists(appUsername));
    }

    @Test
    public void revokePlatformCertificateUsingCertificateByAdminSuccess() throws SecurityException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, UnrecoverableKeyException, OperatorCreationException, JWTCreationException, WrongCredentialsException, NotExistingUserException, ValidationException, InvalidAlgorithmParameterException, InvalidArgumentsException, PlatformManagementException, UserManagementException {
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, csrString);
        String platformCertificate = signCertificateRequestService.signCertificate(certRequest);
        platform.getPlatformAAMCertificate().setCertificateString(platformCertificate);
        platformRepository.save(platform);
        assertNotNull(platformCertificate);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificatePEMString(platformCertificate);

        assertFalse(revokedKeysRepository.exists(platformId));
        RevocationResponse revocationResponse = revocationService.revoke(revocationRequest);

        assertTrue(revocationResponse.isRevoked());
        assertEquals(HttpStatus.OK, revocationResponse.getStatus());
        assertTrue(revokedKeysRepository.exists(platformId));
    }



    @Test
    public void revokeHomeTokenByPlatformSuccess() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, WrongCredentialsException, NotExistingUserException, InvalidKeyException, OperatorCreationException, UnrecoverableKeyException, JWTCreationException, InvalidAlgorithmParameterException, InvalidArgumentsException, PlatformManagementException, UserManagementException, MalformedJWTException, ClassNotFoundException {    // issuing dummy platform token
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().add(platformId);
        userRepository.save(platformOwner);

        KeyPair pair2 = CryptoHelper.createKeyPair();

        platform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAM.getRootCertificate()));
        platformRepository.save(platform);

        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, clientId, new Certificate(), pair2.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));
        // ensure that token is not in revoked token repository
        assertFalse(revokedTokensRepository.exists(dummyHomeToken.getClaims().getId()));
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setHomeTokenString(dummyHomeToken.toString());
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, platformOwnerPassword));
        assertTrue(revocationService.revoke(revocationRequest).isRevoked());
        assertTrue(revokedTokensRepository.exists(dummyHomeToken.getClaims().getId()));
    }

    @Test
    public void revokeHomeTokenByPlatformFailNoRightsToToken() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, WrongCredentialsException, NotExistingUserException, InvalidKeyException, OperatorCreationException, UnrecoverableKeyException, JWTCreationException, InvalidAlgorithmParameterException, InvalidArgumentsException, PlatformManagementException, UserManagementException, MalformedJWTException, ClassNotFoundException {    // issuing dummy platform token
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().add(platformId);
        userRepository.save(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, csrString);
        String certificateString = signCertificateRequestService.signCertificate(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(certificateString));
        platformRepository.save(platform);

        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, platformId, new Certificate(), pair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // ensure that token is not in revoked token repository
        assertFalse(revokedTokensRepository.exists(dummyHomeToken.getClaims().getId()));
        // revocation
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setHomeTokenString(dummyHomeToken.toString());
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, platformOwnerPassword));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeHomeTokeFailWrongToken() throws CertificateException, WrongCredentialsException, NotExistingUserException, ValidationException {
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, platformOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setHomeTokenString("WRONG_TOKEN");
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeFailOnlyCredentialsSent() throws CertificateException, WrongCredentialsException, NotExistingUserException, ValidationException {
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, platformOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeHomeTokeFailWrongCredentials() throws CertificateException, WrongCredentialsException, NotExistingUserException, ValidationException, JWTCreationException {
        savePlatformOwner();
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, wrongPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setHomeTokenString(tokenIssuer.getGuestToken().toString());
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeForeignTokeFailNoToken() throws CertificateException, WrongCredentialsException, NotExistingUserException, ValidationException, JWTCreationException {
        RevocationRequest revocationRequest = new RevocationRequest();
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeFailWrongAAMOwnerPassword() throws CertificateException, WrongCredentialsException, NotExistingUserException, ValidationException {
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, wrongPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeFailAAMOwnerCredentialsOnlySent() throws CertificateException, WrongCredentialsException, NotExistingUserException, ValidationException {
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeHomeTokeFailWrongUser() throws CertificateException, WrongCredentialsException, NotExistingUserException, ValidationException, JWTCreationException {
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(platformOwnerUsername, platformOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setHomeTokenString(tokenIssuer.getGuestToken().toString());
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeForeignTokenSuccess() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException, IOException, TimeoutException, NotExistingUserException, InvalidArgumentsException, WrongCredentialsException, ClassNotFoundException, JWTCreationException, ValidationException, MalformedJWTException {
        addTestUserWithClientCertificateToRepository();
        assertNotNull(userRepository.findOne(username));
        HomeCredentials homeCredentials = new HomeCredentials(null, username, platformId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = new Token(dummyPlatformAAM.getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        assertNotNull(token);

        User platformOwner = savePlatformOwner();
        String platformId = "platform-1";
        Platform platform = new Platform(platformId, serverAddress + "/test", null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().add(platformId);
        userRepository.save(platformOwner);

        Platform dummyPlatform = platformRepository.findOne(platformId);
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAM.getRootCertificate()));
        platformRepository.save(dummyPlatform);

        Set<String> platformsId = new HashSet<>();
        platformsId.add(platformId);

        FederationRule federationRule = new FederationRule("federationId", platformsId);
        federationRulesRepository.save(federationRule);

        Token foreignToken = getTokenService.getForeignToken(token, "", "");
        assertNotNull(foreignToken);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setHomeTokenString(token.toString());
        revocationRequest.setForeignTokenString(foreignToken.toString());

        assertFalse(revokedTokensRepository.exists(foreignToken.getClaims().getId()));
        assertTrue(revocationService.revoke(revocationRequest).isRevoked());
        assertTrue(revokedTokensRepository.exists(foreignToken.getClaims().getId()));
    }

    @Test
    public void revokeForeignTokenFailWrongHomeTokenWrongSubject() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException, IOException, TimeoutException, JWTCreationException, ValidationException, NotExistingUserException, InvalidArgumentsException, WrongCredentialsException, MalformedJWTException, ClassNotFoundException {
        addTestUserWithClientCertificateToRepository();
        assertNotNull(userRepository.findOne(username));
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = new Token(dummyPlatformAAM.getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        assertNotNull(token);

        User platformOwner = savePlatformOwner();
        String platformId = "platform-1";
        Platform platform = new Platform(platformId, serverAddress + "/test", null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().add(platformId);
        userRepository.save(platformOwner);

        Platform dummyPlatform = platformRepository.findOne(platformId);
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAM.getRootCertificate()));
        platformRepository.save(dummyPlatform);

        Set<String> platformsId = new HashSet<>();
        platformsId.add(platformId);
        FederationRule federationRule = new FederationRule("federationId", platformsId);
        federationRulesRepository.save(federationRule);

        Token foreignToken = getTokenService.getForeignToken(token, "", "");
        assertNotNull(foreignToken);

        homeCredentials = new HomeCredentials(null, platformOwnerUsername, clientId, null, userKeyPair.getPrivate());
        loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        token = new Token(dummyPlatformAAM.getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setHomeTokenString(token.toString());
        revocationRequest.setForeignTokenString(foreignToken.toString());

        assertFalse(revokedTokensRepository.exists(foreignToken.getClaims().getId()));
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeUserCertificateUsingCommonNameByAdminSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        signCertificateRequestService.signCertificate(certRequest);
        User user = userRepository.findOne(appUsername);
        assertNotNull(user.getClientCertificates().get(clientId));
        String commonName = appUsername + illegalSign + clientId;

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificateCommonName(commonName);

        assertNotNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        assertNull(revokedKeysRepository.findOne(appUsername));
        //user certificate revocation
        assertTrue(revocationService.revoke(revocationRequest).isRevoked());

        assertNull(userRepository.findOne(appUsername).getClientCertificates().get(clientId));
        assertTrue(revokedKeysRepository.findOne(appUsername).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    @Test
    public void revokePlatformCertificateUsingCommonNameByAdminSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, KeyStoreException, IOException, WrongCredentialsException, UserManagementException, ValidationException, PlatformManagementException, InvalidArgumentsException, NotExistingUserException {
        //platform certificate revoking
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificateString = signCertificateRequestService.signCertificate(certRequest);

        platform.setPlatformAAMCertificate(new Certificate(certificateString));
        platformRepository.save(platform);

        platformOwner.getOwnedPlatforms().add(platformId);
        userRepository.save(platformOwner);

        platformOwner = userRepository.findOne(platformOwnerUsername);
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificateCommonName(platformId);

        assertFalse(platformOwner.getOwnedPlatforms().isEmpty());
        assertFalse(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());

        assertFalse(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        assertNull(revokedKeysRepository.findOne(platformId));

        assertTrue(revocationService.revoke(revocationRequest).isRevoked());

        assertTrue(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().isEmpty());
        assertTrue(revokedKeysRepository.findOne(platformId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())));
    }

    @Test
    public void revokeLocalComponentCertificateUsingCommonNameByAdminSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            CertificateException,
            KeyStoreException {
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);

        String commonName = componentId + illegalSign + SecurityConstants.CORE_AAM_INSTANCE_ID;
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificateCommonName(commonName);
        assertFalse(componentCertificatesRepository.findOne(componentId).getCertificate().getCertificateString().isEmpty());
        assertNull(revokedKeysRepository.findOne(componentId));

        assertTrue(revocationService.revoke(revocationRequest).isRevoked());

        assertNull(componentCertificatesRepository.findOne(componentId));
        assertTrue(revokedKeysRepository.findOne(componentId).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(componentCertificate.getCertificate().getX509().getPublicKey().getEncoded())));
    }

    @Test
    public void revokeLocalComponentCertificateUsingCommonNameByAdminFailNoComponentInDatabase() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            CertificateException,
            KeyStoreException {
        String commonName = componentId + illegalSign + SecurityConstants.CORE_AAM_INSTANCE_ID;
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificateCommonName(commonName);

        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeByAdminFailWrongCommonName() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidArgumentsException, UserManagementException, PlatformManagementException, WrongCredentialsException, NotExistingUserException, CertificateException, KeyStoreException {
        String commonName = componentId + illegalSign + SecurityConstants.CORE_AAM_INSTANCE_ID + illegalSign + "WrongCommonNameEnding";
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificateCommonName(commonName);

        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeCertificateByUserFailWrongCertificate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidArgumentsException, UserManagementException, PlatformManagementException, WrongCredentialsException, NotExistingUserException, CertificateException, KeyStoreException {
        saveUser();
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(appUsername, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString("WrongPEM");

        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeByAdminFailNoArguments() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidArgumentsException, UserManagementException, PlatformManagementException, WrongCredentialsException, NotExistingUserException, CertificateException, KeyStoreException {
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);

        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeLocalComponentCertificateUsingCertificateByAdminSuccessKeyIsRevoked() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            CertificateException,
            KeyStoreException,
            UnrecoverableKeyException,
            ValidationException {
        String cert = CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                "core.p12",
                "registry-core-1"));
        // adding key to revoked repository
        SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne("registry");
        Set<String> keySet = (subjectsRevokedKeys == null) ? new HashSet<>() : subjectsRevokedKeys
                .getRevokedKeysSet();
        keySet.add(Base64.getEncoder().encodeToString(
                CryptoHelper.convertPEMToX509(cert).getPublicKey().getEncoded()));
        revokedKeysRepository.save(new SubjectsRevokedKeys("registry", keySet));

        //register component
        KeyPair keyPair = new KeyPair(CryptoHelper.convertPEMToX509(cert).getPublicKey(), (PrivateKey) getPrivateKeyFromTestKeystore(
                "core.p12",
                "registry-core-1"));
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, certificationAuthorityHelper.getAAMInstanceIdentifier(), keyPair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        String certificateString = signCertificateRequestService.signCertificate(certRequest);

        ComponentCertificate componentCertificate = new ComponentCertificate(
                "registry",
                new Certificate(certificateString));
        componentCertificatesRepository.save(componentCertificate);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificatePEMString(cert);

        assertTrue(revocationService.revoke(revocationRequest).isRevoked());
        assertTrue(revokedKeysRepository.findOne("registry").getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(componentCertificate.getCertificate().getX509().getPublicKey().getEncoded())));
    }

    @Test
    public void revokeLocalComponentCertificateUsingCertificateByAdminSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            CertificateException,
            KeyStoreException {
        ComponentCertificate componentCertificate = new ComponentCertificate(
                "registry",
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificatePEMString(CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                "core.p12",
                "registry-core-1")));
        assertFalse(componentCertificatesRepository.findOne("registry").getCertificate().getCertificateString().isEmpty());
        assertNull(revokedKeysRepository.findOne("registry"));

        assertTrue(revocationService.revoke(revocationRequest).isRevoked());

        assertNull(componentCertificatesRepository.findOne("registry"));
        assertTrue(revokedKeysRepository.findOne("registry").getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(componentCertificate.getCertificate().getX509().getPublicKey().getEncoded())));
    }

    @Test
    public void revokeLocalComponentCertificateUsingCertificateByAdminFailNoCertInDatabase() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            CertificateException,
            KeyStoreException {
        componentCertificatesRepository.delete("registry");
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificatePEMString(CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                "core.p12",
                "registry-core-1")));
        assertNull(componentCertificatesRepository.findOne("registry"));
        assertNull(revokedKeysRepository.findOne("registry"));

        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }

    @Test
    public void revokeLocalComponentCertificateUsingCertificateByAdminFailNotCertSent() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            CertificateException,
            KeyStoreException {
        componentCertificatesRepository.delete("registry");
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificatePEMString(" TEST ");

        assertFalse(revocationService.revoke(revocationRequest).isRevoked());
    }


    @Test
    public void revokeHomeTokenByAdminSuccess() throws SecurityException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, UnrecoverableKeyException, OperatorCreationException, JWTCreationException, WrongCredentialsException, NotExistingUserException, ValidationException {
        addTestUserWithClientCertificateToRepository();

        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setHomeTokenString(homeToken.toString());

        // verify the user token is not yet revoked
        assertFalse(revokedTokensRepository.exists(homeToken.getClaims().getId()));
        // revocation
        revocationService.revoke(revocationRequest);

        // verify the user token is revoked
        assertTrue(revokedTokensRepository.exists(homeToken.getClaims().getId()));
    }

    @Test
    public void revokeFailEmptyUserCredentials() {
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials());
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        assertFalse(revocationService.revoke(revocationRequest).isRevoked());

    }

    private X509Certificate getCertificateFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
    }

    private Key getPrivateKeyFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return pkcs12Store.getKey(certificateAlias, KEY_STORE_PASSWORD.toCharArray());
    }
}