package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.SignCertificateRequestService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

import static eu.h2020.symbiote.security.commons.SecurityConstants.CORE_AAM_INSTANCE_ID;
import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.*;

/**
 * Test suite for generic AAM functionality irrelevant to actual deployment type (Core or Platform)
 *
 * @author Piotr Kicki (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@TestPropertySource("/core.properties")
public class CertificatesIssuingUnitTests extends
        AbstractAAMTestSuite {

    private final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

    @Autowired
    private CertificationAuthorityHelper certificationAuthorityHelper;
    @Autowired
    private SignCertificateRequestService signCertificateRequestService;

    @Test
    public void generateCertificateFromCSRSuccess() throws OperatorCreationException, CertificateException,
            UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException,
            InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        KeyPairGenerator g = KeyPairGenerator.getInstance(SecurityConstants.KEY_PAIR_GEN_ALGORITHM, PROVIDER_NAME);
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(SecurityConstants.CURVE_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = g.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        X509Certificate cert = certificationAuthorityHelper.generateCertificateFromCSR(csr, false);
        assertNotNull(cert);
    }

    @Test
    public void generateCertificateFromCSRCorrectSubjectTest() throws OperatorCreationException,
            CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchProviderException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        KeyPairGenerator g = KeyPairGenerator.getInstance(SecurityConstants.KEY_PAIR_GEN_ALGORITHM, PROVIDER_NAME);
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(SecurityConstants.CURVE_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = g.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        X509Certificate cert = certificationAuthorityHelper.generateCertificateFromCSR(csr, false);
        assertEquals(new X500Name(cert.getSubjectDN().getName()), csr.getSubject());
    }

    @Test
    public void generateCertificateFromCSRPublicKeyTest() throws OperatorCreationException, CertificateException,
            UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException,
            InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        KeyPairGenerator g = KeyPairGenerator.getInstance(SecurityConstants.KEY_PAIR_GEN_ALGORITHM, PROVIDER_NAME);
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(SecurityConstants.CURVE_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = g.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        X509Certificate cert = certificationAuthorityHelper.generateCertificateFromCSR(csr, false);
        assertEquals(keyPair.getPublic(), cert.getPublicKey());
    }

    @Test
    public void generatedCertificateCreationAndVerification() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance(SecurityConstants.KEY_PAIR_GEN_ALGORITHM, PROVIDER_NAME);
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(SecurityConstants.CURVE_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = g.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        X509Certificate cert = certificationAuthorityHelper.generateCertificateFromCSR(csr, false);
        cert.verify(certificationAuthorityHelper.getAAMPublicKey());

        cert.checkValidity(new Date());
    }


    @Test(expected = WrongCredentialsException.class)
    public void getCertificateWrongCredentialsFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {
        User user = saveUser();

        KeyPair pair = CryptoHelper.createKeyPair();

        String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(),
                user.getUsername(), clientId, pair);
        CertificateRequest certRequest = new CertificateRequest(appUsername, wrongpassword, clientId, csr);
        signCertificateRequestService.getCertificate(certRequest);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void getCertificateWrongSubjectInCSRFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            CertificateException,
            UserManagementException,
            PlatformManagementException {

        saveUser();

        KeyPair pair = CryptoHelper.createKeyPair();

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/platform_1.p12"), "1234567".toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate("platform-1-1-c1");

        String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificate, username, clientId, pair);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csr);

        signCertificateRequestService.getCertificate(certRequest);
    }

    @Test(expected = NotExistingUserException.class)
    public void getClientCertificateNotExistingUserFailure() throws
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            UserManagementException,
            PlatformManagementException {
        //ensure that there are no users in repo
        userRepository.deleteAll();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        signCertificateRequestService.getCertificate(certRequest);
    }

    @Test(expected = ValidationException.class)
    public void getClientCertificateRevokedKeyFailure() throws
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            UserManagementException,
            PlatformManagementException {

        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(x509Certificate.getPublicKey().getEncoded()));
        revokedKeysRepository.save(new SubjectsRevokedKeys(appUsername, keySet));
        signCertificateRequestService.getCertificate(certRequest);
    }


    @Test
    public void getPlatformCertificateWrongUserRoleFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException {
        User platformOwner = savePlatformOwner();
        User user = saveUser();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(user.getUsername(), password, clientId, csrString);
        try {
            signCertificateRequestService.getCertificate(certRequest);
        } catch (Exception e) {
            assertEquals(PlatformManagementException.class, e.getClass());
            assertEquals("User is not a Platform Owner", e.getMessage());
        }
    }

    @Test
    public void getPlatformCertificateNotExistingPlatformFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException {
        //ensure that platform repo is empty
        platformRepository.deleteAll();

        savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        try {
            signCertificateRequestService.getCertificate(certRequest);
        } catch (Exception e) {
            assertEquals(PlatformManagementException.class, e.getClass());
            assertEquals("Platform doesn't exist", e.getMessage());
        }
    }

    //replacing previous certificate with new one
    @Test
    public void replaceCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {

        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);
        User user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + appUsername + illegalSign + clientId + illegalSign + certificationAuthorityHelper.getAAMInstanceIdentifier(), x509Certificate.getSubjectDN().getName());
        // -1 for end certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        //adding next certificate with the same public key
        String certificate2 = signCertificateRequestService.getCertificate(certRequest);
        assertNotNull(certificate2);
        user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());

        X509Certificate x509Certificate2 = CryptoHelper.convertPEMToX509(certificate);
        assertEquals(x509Certificate.getPublicKey(), x509Certificate2.getPublicKey());
    }

    //adding next certificate
    @Test
    public void addCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {

        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);
        User user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + appUsername + illegalSign + clientId + illegalSign + certificationAuthorityHelper.getAAMInstanceIdentifier(), x509Certificate.getSubjectDN().getName());
        // -1 for end certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        //adding next certificate with different public key
        KeyPair pair2 = CryptoHelper.createKeyPair();
        String csrString2 = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair2);
        assertNotNull(csrString);
        CertificateRequest certRequest2 = new CertificateRequest(appUsername, password, clientId, csrString2);
        String certificate2 = signCertificateRequestService.getCertificate(certRequest2);
        assertNotNull(certificate2);
        assertNotEquals(certificate, certificate2);

        user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());

        X509Certificate x509Certificate2 = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate2);
    }

    //getting first certificate
    @Test
    public void getNewCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {

        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + appUsername + illegalSign + clientId + illegalSign + certificationAuthorityHelper.getAAMInstanceIdentifier(), x509Certificate.getSubjectDN().getName());
        // -1 for end certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
    }

    @Test
    public void getPlatformCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {

        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platformId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());
    }

    @Test
    public void replacePlatformCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {

        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platformId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());

        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platformId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());
    }

    @Test
    public void getPlatformComponentCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {

        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + platformId, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
    }

    @Test
    public void getComponentCertificateNotExistingPlatformFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException {
        //ensure that platform repo is empty
        platformRepository.deleteAll();

        savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        try {
            signCertificateRequestService.getCertificate(certRequest);
        } catch (Exception e) {
            assertEquals(PlatformManagementException.class, e.getClass());
            assertEquals("Platform doesn't exist", e.getMessage());
        }
    }

    @Test
    public void getComponentCertificateWrongUserRoleFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException {
        User platformOwner = savePlatformOwner();
        User user = saveUser();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(user.getUsername(), password, clientId, csrString);
        try {
            signCertificateRequestService.getCertificate(certRequest);
        } catch (Exception e) {
            assertEquals(PlatformManagementException.class, e.getClass());
            assertEquals("User is not a Platform Owner", e.getMessage());
        }
    }

    @Test
    public void revokeAndReplacePlatformComponentCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {

        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + platformId, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + platformId, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
    }

    @Test
    public void replacePlatformComponentCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {

        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + platformId, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + platformId, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
    }

    @Test
    public void getCoreComponentCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {

        User AAMOwner = new User();
        AAMOwner.setUsername(AAMOwnerUsername);
        AAMOwner.setPasswordEncrypted(AAMOwnerPassword);
        AAMOwner.setRecoveryMail(recoveryMail);
        AAMOwner.setClientCertificates(new HashMap<>());
        AAMOwner.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(AAMOwner);
        Platform platform = new Platform(CORE_AAM_INSTANCE_ID, null, null, AAMOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        AAMOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(AAMOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
        assertNotNull(componentCertificatesRepository.findOne(componentId));
    }

    @Test
    public void revokeAndReplaceCoreComponentCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {

        User AAMOwner = new User();
        AAMOwner.setUsername(AAMOwnerUsername);
        AAMOwner.setPasswordEncrypted(AAMOwnerPassword);
        AAMOwner.setRecoveryMail(recoveryMail);
        AAMOwner.setClientCertificates(new HashMap<>());
        AAMOwner.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(AAMOwner);
        Platform platform = new Platform(CORE_AAM_INSTANCE_ID, null, null, AAMOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        AAMOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(AAMOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
    }

    @Test
    public void replaceCoreComponentCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {

        User AAMOwner = new User();
        AAMOwner.setUsername(AAMOwnerUsername);
        AAMOwner.setPasswordEncrypted(AAMOwnerPassword);
        AAMOwner.setRecoveryMail(recoveryMail);
        AAMOwner.setClientCertificates(new HashMap<>());
        AAMOwner.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(AAMOwner);
        Platform platform = new Platform(CORE_AAM_INSTANCE_ID, null, null, AAMOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        AAMOwner.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(AAMOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
    }

    @Test
    public void revokeAndReplaceAAMOwnerCertificate() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {
        //  Register AAM Owner
        User aamowner = new User();
        aamowner.setUsername(AAMOwnerUsername);
        aamowner.setPasswordEncrypted(passwordEncoder.encode(AAMOwnerPassword));
        aamowner.setRecoveryMail(recoveryMail);
        aamowner.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(aamowner);

        Platform platform = new Platform(CORE_AAM_INSTANCE_ID, null, null, aamowner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        aamowner.getOwnedPlatforms().put(CORE_AAM_INSTANCE_ID, platform);
        userRepository.save(aamowner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        signCertificateRequestService.getCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
    }
}