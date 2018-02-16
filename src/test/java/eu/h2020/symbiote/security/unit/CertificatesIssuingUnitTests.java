package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
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
    @Autowired
    private RevokedKeysRepository revokedKeysRepository;

    @Test
    public void generateCertificateFromCSRSuccess() throws
            OperatorCreationException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException {
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
    public void generateCertificateFromCSRCorrectSubjectTest() throws
            OperatorCreationException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException {
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
    public void generateCertificateFromCSRPublicKeyTest() throws
            OperatorCreationException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException {
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
    public void generatedCertificateCreationAndVerification() throws
            Exception {
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

    @Test
    public void getClientCertificateSuccess() throws
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
        String certificate = signCertificateRequestService.signCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + appUsername + illegalSign + clientId + illegalSign + certificationAuthorityHelper.getAAMInstanceIdentifier(), x509Certificate.getSubjectDN().getName());
        // -1 for end certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
    }

    @Test(expected = ValidationException.class)
    public void getClientCertificateWrongSubjectInCSRFailure() throws
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

        String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificate, appUsername, clientId, pair);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csr);

        signCertificateRequestService.signCertificate(certRequest);
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
        signCertificateRequestService.signCertificate(certRequest);
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
        String certificate = signCertificateRequestService.signCertificate(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(x509Certificate.getPublicKey().getEncoded()));
        revokedKeysRepository.save(new SubjectsRevokedKeys(appUsername, keySet));
        signCertificateRequestService.signCertificate(certRequest);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getClientCertificateWrongCredentialsFailure() throws
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
        CertificateRequest certRequest = new CertificateRequest(appUsername, wrongPassword, clientId, csr);
        signCertificateRequestService.signCertificate(certRequest);
    }

    @Test
    public void getLocalComponentCertificateSuccess() throws
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

        // initial issue
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
        assertNotNull(componentCertificatesRepository.findOne(componentId));

        // override check
        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        certificate = signCertificateRequestService.signCertificate(certRequest);
        assertTrue(componentCertificatesRepository.exists(componentId));
        assertEquals(componentCertificatesRepository.findOne(componentId).getCertificate().getCertificateString(), certificate);

    }

    @Test(expected = WrongCredentialsException.class)
    public void getLocalComponentCertificateWrongCredentialsFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            IOException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            UserManagementException,
            PlatformManagementException {
        KeyPair pair = CryptoHelper.createKeyPair();
        String csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, wrongPassword, clientId, csr);
        signCertificateRequestService.signCertificate(certRequest);
    }

    @Test(expected = ValidationException.class)
    public void getLocalComponentCertificateWrongSubjectInCSRFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            CertificateException,
            UserManagementException,
            PlatformManagementException {
        KeyPair pair = CryptoHelper.createKeyPair();
        String csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csr);
        signCertificateRequestService.signCertificate(certRequest);
    }

    @Test(expected = ValidationException.class)
    public void getLocalComponentCertificateRevokedKeyCSRFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            CertificateException,
            UserManagementException,
            PlatformManagementException {
        KeyPair pair = CryptoHelper.createKeyPair();
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        revokedKeysRepository.save(new SubjectsRevokedKeys(CORE_AAM_INSTANCE_ID, keySet));
        String csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csr);
        signCertificateRequestService.signCertificate(certRequest);
    }

    @Test(expected = PlatformManagementException.class)
    public void getLocalComponentCertificateWrongComponentIdFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            CertificateException,
            UserManagementException,
            PlatformManagementException {
        KeyPair pair = CryptoHelper.createKeyPair();
        String csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(SecurityConstants.AAM_COMPONENT_NAME, CORE_AAM_INSTANCE_ID, pair);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csr);
        signCertificateRequestService.signCertificate(certRequest);
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
        savePlatform(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platformId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());
    }

    @Test
    public void getPlatformCertificateWrongUserRoleFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException {
        User platformOwner = savePlatformOwner();
        User user = saveUser();
        savePlatform(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(user.getUsername(), password, clientId, csrString);
        try {
            signCertificateRequestService.signCertificate(certRequest);
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
            IOException,
            InvalidArgumentsException {
        //ensure that platform repo is empty
        platformRepository.deleteAll();

        savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        try {
            signCertificateRequestService.signCertificate(certRequest);
        } catch (Exception e) {
            assertEquals(PlatformManagementException.class, e.getClass());
            assertEquals(PlatformManagementException.PLATFORM_NOT_EXIST, e.getMessage());
        }
    }

    @Test(expected = ValidationException.class)
    public void getPlatformCertificateRevokedKeyFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException,
            CertificateException,
            WrongCredentialsException,
            UserManagementException,
            ValidationException,
            PlatformManagementException,
            NotExistingUserException {
        //ensure that platform repo is empty
        platformRepository.deleteAll();
        savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);

        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        revokedKeysRepository.save(new SubjectsRevokedKeys(platformId, keySet));
        signCertificateRequestService.signCertificate(certRequest);
    }

    @Test
    public void replaceClientCertificateUsingNewKeysSuccess() throws
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
        String certificate = signCertificateRequestService.signCertificate(certRequest);
        User user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + appUsername + illegalSign + clientId + illegalSign + certificationAuthorityHelper.getAAMInstanceIdentifier(), x509Certificate.getSubjectDN().getName());
        // -1 for end certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        //adding next certificate with different public key
        pair = CryptoHelper.createKeyPair();
        String csrString2 = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest2 = new CertificateRequest(appUsername, password, clientId, csrString2);
        String certificate2 = signCertificateRequestService.signCertificate(certRequest2);
        assertNotNull(certificate2);
        assertNotEquals(certificate, certificate2);

        user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());

        X509Certificate x509Certificate2 = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate2);
    }

    //replacing previous certificate with new one
    @Test
    public void replaceClientCertificateUsingExistingKeysSuccess() throws
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
        String certificate = signCertificateRequestService.signCertificate(certRequest);
        User user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + appUsername + illegalSign + clientId + illegalSign + certificationAuthorityHelper.getAAMInstanceIdentifier(), x509Certificate.getSubjectDN().getName());
        // -1 for end certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        //adding next certificate with the same public key
        String certificate2 = signCertificateRequestService.signCertificate(certRequest);
        assertNotNull(certificate2);
        user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());

        X509Certificate x509Certificate2 = CryptoHelper.convertPEMToX509(certificate);
        assertEquals(x509Certificate.getPublicKey(), x509Certificate2.getPublicKey());
        assertFalse(revokedKeysRepository.exists(appUsername));
    }

    @Test
    public void replacePlatformCertificateUsingNewKeysSuccess() throws
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
        savePlatform(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platformId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());
        assertTrue(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().equals(certificate));

        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        certificate = signCertificateRequestService.signCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platformId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());
    }

    @Test
    public void replacePlatformCertificateUsingExistingKeysSuccess() throws
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
        savePlatform(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platformId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());

        csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        certificate = signCertificateRequestService.signCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platformId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());
        // pair should not be revoked
        assertFalse(revokedKeysRepository.exists(platformId));
    }

    @Test
    public void replaceLocalComponentCertificateUsingNewKeysSuccess() throws
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

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        KeyPair oldPair = pair;
        // new pair!
        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        certificate = signCertificateRequestService.signCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
    }

    @Test
    public void replaceLocalComponentCertificateUsingExistingKeysSuccess() throws
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

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        //generating new certificate with the same keypair
        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        certificate = signCertificateRequestService.signCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + illegalSign + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
        // pair should not be revoked
        assertFalse(revokedKeysRepository.exists(componentId));
    }


    private void savePlatform(User platformOwner) {
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedServices().add(platformId);
        userRepository.save(platformOwner);
    }


}