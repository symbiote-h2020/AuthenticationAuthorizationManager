package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.SignCertificateRequestService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.bouncycastle.asn1.x500.X500Name;
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
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static eu.h2020.symbiote.security.commons.SecurityConstants.CORE_AAM_INSTANCE_ID;
import static eu.h2020.symbiote.security.helpers.CryptoHelper.FIELDS_DELIMITER;
import static eu.h2020.symbiote.security.helpers.CryptoHelper.createKeyPair;
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
            InvalidAlgorithmParameterException,
            SignatureException,
            InvalidKeyException {

        KeyPair keyPair = createKeyPair();
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        X509Certificate cert = certificationAuthorityHelper.generateCertificateFromCSR(csr, false);
        //verify content and validity of the certificate
        assertNotNull(cert);
        assertEquals(new X500Name(cert.getSubjectDN().getName()), csr.getSubject());
        assertEquals(keyPair.getPublic(), cert.getPublicKey());
        cert.verify(certificationAuthorityHelper.getAAMPublicKey());
        cert.checkValidity(new Date());
    }

    @Test(expected = WrongCredentialsException.class)
    public void getClientCertificateFailForAccountNotActivate() throws
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
            ServiceManagementException {

        saveNewUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        signCertificateRequestService.signCertificateRequest(certRequest);
    }

    @Test
    public void getClientCertificateSuccess() throws
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
            ServiceManagementException {

        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + appUsername + FIELDS_DELIMITER + clientId + FIELDS_DELIMITER + certificationAuthorityHelper.getAAMInstanceIdentifier(), x509Certificate.getSubjectDN().getName());
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
            ServiceManagementException {

        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        // get other platform certificate
        X509Certificate certificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");

        String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificate, appUsername, clientId, pair);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csr);

        signCertificateRequestService.signCertificateRequest(certRequest);
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
            IOException,
            UserManagementException,
            ServiceManagementException {
        //ensure that there is not our user in repo
        assertFalse(userRepository.exists(appUsername));
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        signCertificateRequestService.signCertificateRequest(certRequest);
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
            IOException,
            UserManagementException,
            ServiceManagementException {

        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        // revoke public key
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        revokedKeysRepository.save(new SubjectsRevokedKeys(appUsername, keySet));
        // try to issue certificate using revoked key
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        signCertificateRequestService.signCertificateRequest(certRequest);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getClientCertificateWrongCredentialsFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            IOException,
            InvalidArgumentsException,
            NotExistingUserException,
            ValidationException,
            UserManagementException,
            ServiceManagementException,
            WrongCredentialsException {
        User user = saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();

        String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(),
                user.getUsername(), clientId, pair);
        CertificateRequest certRequest = new CertificateRequest(appUsername, wrongPassword, clientId, csr);
        signCertificateRequestService.signCertificateRequest(certRequest);
    }

    @Test(expected = ValidationException.class)
    public void getClientCertificateMismatchOfClientIdFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            IOException,
            InvalidArgumentsException,
            NotExistingUserException,
            ValidationException,
            UserManagementException,
            ServiceManagementException,
            WrongCredentialsException {
        User user = saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(),
                user.getUsername(), clientId, pair);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, wrongClientId, csr);
        signCertificateRequestService.signCertificateRequest(certRequest);
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
            ServiceManagementException {

        // initial issue
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, "", csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + FIELDS_DELIMITER + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
        assertNotNull(componentCertificatesRepository.findOne(componentId));

        // override check
        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, clientId, csrString);
        certificate = signCertificateRequestService.signCertificateRequest(certRequest);
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
            ServiceManagementException {
        KeyPair pair = CryptoHelper.createKeyPair();
        String csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, wrongPassword, "", csr);
        signCertificateRequestService.signCertificateRequest(certRequest);
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
            ServiceManagementException {
        KeyPair pair = CryptoHelper.createKeyPair();
        String csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, "", csr);
        signCertificateRequestService.signCertificateRequest(certRequest);
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
            ServiceManagementException {
        KeyPair pair = CryptoHelper.createKeyPair();
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        revokedKeysRepository.save(new SubjectsRevokedKeys(CORE_AAM_INSTANCE_ID, keySet));
        String csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, "", csr);
        signCertificateRequestService.signCertificateRequest(certRequest);
    }

    @Test(expected = ServiceManagementException.class)
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
            ServiceManagementException {
        KeyPair pair = CryptoHelper.createKeyPair();
        String csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(SecurityConstants.AAM_COMPONENT_NAME, CORE_AAM_INSTANCE_ID, pair);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, "", csr);
        signCertificateRequestService.signCertificateRequest(certRequest);
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
            ServiceManagementException {

        User platformOwner = savePlatformOwner();
        savePlatform(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);

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
        User user = saveUser();
        savePlatform(user);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(user.getUsername(), password, "", csrString);
        try {
            signCertificateRequestService.signCertificateRequest(certRequest);
        } catch (Exception e) {
            assertEquals(ServiceManagementException.class, e.getClass());
            assertEquals(ServiceManagementException.NO_RIGHTS, e.getMessage());
        }
    }

    @Test
    public void getPlatformCertificateNotExistingPlatformFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException {

        User user = savePlatformOwner();
        user.getOwnedServices().add(platformId);
        userRepository.save(user);
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, csrString);
        try {
            signCertificateRequestService.signCertificateRequest(certRequest);
        } catch (Exception e) {
            assertEquals(ServiceManagementException.class, e.getClass());
            assertEquals(ServiceManagementException.SERVICE_NOT_EXIST, e.getMessage());
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
            ServiceManagementException,
            NotExistingUserException {
        //ensure that platform repo is empty
        platformRepository.deleteAll();
        savePlatformOwner();
        KeyPair pair = CryptoHelper.createKeyPair();
        //put key into the repo
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        revokedKeysRepository.save(new SubjectsRevokedKeys(platformId, keySet));

        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, "", csrString);

        signCertificateRequestService.signCertificateRequest(certRequest);
    }

    @Test
    public void getSmartSpaceCertificateSuccess() throws
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
            ServiceManagementException {

        User smartSpaceOwner = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.ACTIVE);
        userRepository.save(smartSpaceOwner);
        saveSmartSpace(smartSpaceOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(preferredSmartSpaceId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(smartSpaceOwnerUsername, smartSpaceOwnerPassword, preferredSmartSpaceId, csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + preferredSmartSpaceId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());
    }

    @Test
    public void getSmartSpaceCertificateWrongUserRoleFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException {
        User smartSpaceOwner = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.USER, AccountStatus.ACTIVE);
        userRepository.save(smartSpaceOwner);
        saveSmartSpace(smartSpaceOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(preferredSmartSpaceId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(smartSpaceOwnerUsername, smartSpaceOwnerPassword, preferredSmartSpaceId, csrString);
        try {
            signCertificateRequestService.signCertificateRequest(certRequest);
        } catch (Exception e) {
            assertEquals(ServiceManagementException.class, e.getClass());
            assertEquals(ServiceManagementException.NO_RIGHTS, e.getMessage());
        }
    }

    @Test
    public void getSmartSpaceCertificateUserNotOwnSmartSpaceFail() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException {
        User serviceOwner = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.ACTIVE);
        userRepository.save(serviceOwner);

        User user = saveUser();
        SmartSpace smartSpace = new SmartSpace(preferredSmartSpaceId,
                smartSpaceInstanceFriendlyName,
                smartSpaceGateWayAddress,
                isExposingSiteLocalAddress,
                smartSpaceSiteLocalAddress,
                new Certificate(),
                new HashMap<>(),
                user);
        smartSpaceRepository.save(smartSpace);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(preferredSmartSpaceId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(smartSpaceOwnerUsername, smartSpaceOwnerPassword, preferredSmartSpaceId, csrString);
        try {
            signCertificateRequestService.signCertificateRequest(certRequest);
        } catch (Exception e) {
            assertEquals(ServiceManagementException.class, e.getClass());
            assertEquals(ServiceManagementException.NO_RIGHTS, e.getMessage());
        }
    }

    @Test
    public void getSmartSpaceCertificateNotExistingSmartSpaceFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException {
        User user = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.ACTIVE);
        user.getOwnedServices().add(preferredSmartSpaceId);
        userRepository.save(user);
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(preferredSmartSpaceId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(smartSpaceOwnerUsername, smartSpaceOwnerPassword, preferredSmartSpaceId, csrString);
        try {
            signCertificateRequestService.signCertificateRequest(certRequest);
        } catch (Exception e) {
            assertEquals(ServiceManagementException.class, e.getClass());
            assertEquals(ServiceManagementException.SERVICE_NOT_EXIST, e.getMessage());
        }
    }

    @Test(expected = ValidationException.class)
    public void getSmartSpaceCertificateRevokedKeyFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException,
            CertificateException,
            WrongCredentialsException,
            UserManagementException,
            ValidationException,
            ServiceManagementException,
            NotExistingUserException {
        //ensure that smartSpace repo is empty
        smartSpaceRepository.deleteAll();
        User user = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.NEW);
        userRepository.save(user);
        KeyPair pair = CryptoHelper.createKeyPair();
        //revoke public key
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        revokedKeysRepository.save(new SubjectsRevokedKeys(preferredSmartSpaceId, keySet));

        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(preferredSmartSpaceId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(smartSpaceOwnerUsername, smartSpaceOwnerPassword, "", csrString);
        signCertificateRequestService.signCertificateRequest(certRequest);
    }

    @Test
    public void replaceClientCertificateUsingNewKeysSuccess() throws
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
            ServiceManagementException {

        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);
        User user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + appUsername + FIELDS_DELIMITER + clientId + FIELDS_DELIMITER + certificationAuthorityHelper.getAAMInstanceIdentifier(), x509Certificate.getSubjectDN().getName());
        // -1 for end certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        //adding next certificate with different public key
        pair = CryptoHelper.createKeyPair();
        String csrString2 = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest2 = new CertificateRequest(appUsername, password, clientId, csrString2);
        String certificate2 = signCertificateRequestService.signCertificateRequest(certRequest2);
        assertNotNull(certificate2);
        assertNotEquals(certificate, certificate2);

        user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());
        assertEquals(certificate2, user.getClientCertificates().get(clientId).getCertificateString());
    }

    //replacing previous certificate with new one
    @Test
    public void replaceClientCertificateUsingExistingKeysSuccess() throws
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
            ServiceManagementException {

        saveUser();
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);
        User user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + appUsername + FIELDS_DELIMITER + clientId + FIELDS_DELIMITER + certificationAuthorityHelper.getAAMInstanceIdentifier(), x509Certificate.getSubjectDN().getName());
        // -1 for end certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        //adding next certificate with the same public key
        String certificate2 = signCertificateRequestService.signCertificateRequest(certRequest);
        assertNotNull(certificate2);
        user = userRepository.findOne(appUsername);
        assertEquals(1, user.getClientCertificates().size());

        X509Certificate x509Certificate2 = CryptoHelper.convertPEMToX509(certificate);
        assertEquals(x509Certificate.getPublicKey(), x509Certificate2.getPublicKey());
        // pair should not be revoked
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
            ServiceManagementException {

        User platformOwner = savePlatformOwner();
        savePlatform(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platformId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());
        assertTrue(platformRepository.findOne(platformId).getPlatformAAMCertificate().getCertificateString().equals(certificate));

        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, csrString);
        certificate = signCertificateRequestService.signCertificateRequest(certRequest);

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
            ServiceManagementException {

        User platformOwner = savePlatformOwner();
        savePlatform(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platformId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());

        csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platformId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, csrString);
        certificate = signCertificateRequestService.signCertificateRequest(certRequest);

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
    public void replaceSmartSpaceCertificateUsingNewKeysSuccess() throws
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
            ServiceManagementException {

        User smartSpaceOwner = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.ACTIVE);
        saveSmartSpace(smartSpaceOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(preferredSmartSpaceId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(smartSpaceOwnerUsername, smartSpaceOwnerPassword, preferredSmartSpaceId, csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + preferredSmartSpaceId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());
        assertTrue(smartSpaceRepository.findOne(preferredSmartSpaceId).getLocalCertificationAuthorityCertificate().getCertificateString().equals(certificate));

        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(preferredSmartSpaceId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(smartSpaceOwnerUsername, smartSpaceOwnerPassword, preferredSmartSpaceId, csrString);
        certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + preferredSmartSpaceId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());
    }

    @Test
    public void replaceSmartSpaceCertificateUsingExistingKeysSuccess() throws
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
            ServiceManagementException {

        User smartSpaceOwner = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.ACTIVE);
        saveSmartSpace(smartSpaceOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(preferredSmartSpaceId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(smartSpaceOwnerUsername, smartSpaceOwnerPassword, preferredSmartSpaceId, csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + preferredSmartSpaceId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());

        csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(preferredSmartSpaceId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(smartSpaceOwnerUsername, smartSpaceOwnerPassword, preferredSmartSpaceId, csrString);
        certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + preferredSmartSpaceId, x509Certificate.getSubjectDN().getName());
        // 0 for intermediate CA certificate
        assertEquals(0, x509Certificate.getBasicConstraints());
        // pair should not be revoked
        assertFalse(revokedKeysRepository.exists(preferredSmartSpaceId));
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
            ServiceManagementException {

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, "", csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + FIELDS_DELIMITER + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        // new pair!
        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, "", csrString);
        certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + FIELDS_DELIMITER + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
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
            ServiceManagementException {

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, "", csrString);
        String certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + FIELDS_DELIMITER + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());

        //generating new certificate with the same keypair
        csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, CORE_AAM_INSTANCE_ID, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(AAMOwnerUsername, AAMOwnerPassword, "", csrString);
        certificate = signCertificateRequestService.signCertificateRequest(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + FIELDS_DELIMITER + CORE_AAM_INSTANCE_ID, x509Certificate.getSubjectDN().getName());
        // -1 for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
        // pair should not be revoked
        assertFalse(revokedKeysRepository.exists(CORE_AAM_INSTANCE_ID));
    }


    private void savePlatform(User platformOwner) {
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedServices().add(platformId);
        userRepository.save(platformOwner);
    }

    private void saveSmartSpace(User smartSpaceOwner) throws InvalidArgumentsException {
        SmartSpace smartSpace = new SmartSpace(preferredSmartSpaceId,
                smartSpaceInstanceFriendlyName,
                smartSpaceGateWayAddress,
                isExposingSiteLocalAddress,
                smartSpaceSiteLocalAddress,
                new Certificate(),
                new HashMap<>(),
                smartSpaceOwner);
        smartSpaceRepository.save(smartSpace);
        smartSpaceOwner.getOwnedServices().add(preferredSmartSpaceId);
        userRepository.save(smartSpaceOwner);
    }

}