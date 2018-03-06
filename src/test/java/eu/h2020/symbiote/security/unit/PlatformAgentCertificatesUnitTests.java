package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.IssueCertificateService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static eu.h2020.symbiote.security.commons.SecurityConstants.PLATFORM_AGENT_IDENTIFIER_PREFIX;
import static eu.h2020.symbiote.security.helpers.CryptoHelper.FIELDS_DELIMITER;
import static org.junit.Assert.*;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doReturn;

@TestPropertySource("/smart_space.properties")
public class PlatformAgentCertificatesUnitTests extends AbstractAAMTestSuite {

    @SpyBean
    CertificationAuthorityHelper certificationAuthorityHelper;

    @Autowired
    IssueCertificateService issueCertificateService;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        doCallRealMethod().when(certificationAuthorityHelper).getDeploymentType();
    }

    @Test
    public void getPlatformAgentCertificateSuccess() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ServiceManagementException {

        User platformAgent = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(platformAgent);

        KeyPair pair = CryptoHelper.createKeyPair();
        String componentId = PLATFORM_AGENT_IDENTIFIER_PREFIX + "component";
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        String certificate = issueCertificateService.issueCertificate(certRequest);

        assertTrue(certificate.contains("BEGIN CERTIFICATE"));
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(certificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + componentId + FIELDS_DELIMITER + platformId, x509Certificate.getSubjectDN().getName());
        // -1  for intermediate CA certificate
        assertEquals(-1, x509Certificate.getBasicConstraints());
    }

    @Test(expected = ValidationException.class)
    public void getPlatformAgentCertificateFailWrongComponentName() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ServiceManagementException {


        User platformAgent = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(platformAgent);

        KeyPair pair = CryptoHelper.createKeyPair();
        String componentId = "WrongComponentId";
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        issueCertificateService.issueCertificate(certRequest);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void getPlatformAgentCertificateFailWrongDeploymentId() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ServiceManagementException {

        //deploymentId should be SMART_SPACE, not PLATFORM
        doReturn(IssuingAuthorityType.PLATFORM).when(certificationAuthorityHelper).getDeploymentType();
        User platformAgent = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(platformAgent);

        KeyPair pair = CryptoHelper.createKeyPair();
        String componentId = PLATFORM_AGENT_IDENTIFIER_PREFIX + "component";
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        issueCertificateService.issueCertificate(certRequest);
    }

    @Test(expected = ValidationException.class)
    public void getPlatformAgentCertificateFailWrongPAPassword() throws
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ServiceManagementException {

        User platformAgent = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.USER);
        userRepository.save(platformAgent);

        KeyPair pair = CryptoHelper.createKeyPair();
        String componentId = PLATFORM_AGENT_IDENTIFIER_PREFIX + "component";
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, "wrong" + platformOwnerPassword, clientId, csrString);
        issueCertificateService.issueCertificate(certRequest);
    }
}
