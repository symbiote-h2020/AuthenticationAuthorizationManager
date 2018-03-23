package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doReturn;

@TestPropertySource("/core.properties")
public class AAMServicesUnitTests extends AbstractAAMTestSuite {

    @SpyBean
    CertificationAuthorityHelper certificationAuthorityHelper;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Autowired
    AAMServices aamServices;
    private User platformOwner;
    private User smartSpaceOwner;
    private String oldSiteLocalAddress;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        doCallRealMethod().when(certificationAuthorityHelper).getDeploymentType();
        doCallRealMethod().when(certificationAuthorityHelper).getAAMInstanceIdentifier();
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", coreInterfaceAddress);
        oldSiteLocalAddress = (String) ReflectionTestUtils.getField(aamServices, "siteLocalAddress");
        //registration of the users used in tests
        platformOwner = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        smartSpaceOwner = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(platformOwner);
        userRepository.save(smartSpaceOwner);
    }

    @After
    public void after() {
        ReflectionTestUtils.setField(aamServices, "siteLocalAddress", oldSiteLocalAddress);
    }

    @Test
    public void getAvailableAAMsAsCoreWithNoRegisteredServicesSuccess() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            AAMException {

        // injecting core component certificate
        String componentId = "registry";
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "keystores/core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);

        Map<String, AAM> aams = aamServices.getAvailableAAMs();
        // there should be only core AAM in the list
        assertEquals(1, aams.size());
        // verifying the contents
        AAM aam = aams.get(SecurityConstants.CORE_AAM_INSTANCE_ID);
        assertNotNull(aam);
        assertEquals(SecurityConstants.CORE_AAM_INSTANCE_ID, aam.getAamInstanceId());
        assertEquals(coreInterfaceAddress, aam.getAamAddress());
        assertEquals(SecurityConstants.CORE_AAM_FRIENDLY_NAME, aam.getAamInstanceFriendlyName());
        assertEquals(certificationAuthorityHelper.getAAMCert(), aam.getAamCACertificate().getCertificateString());

        // should contain one component certificate
        assertEquals(1, aam.getComponentCertificates().size());
        assertEquals(componentCertificate.getCertificate().getCertificateString(), aam.getComponentCertificates().get(componentId).getCertificateString());
    }

    @Test
    public void getAvailableAAMsByCoreWithRegisteredServicesSuccess() throws
            SecurityException,
            IOException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException {


        // issue platform registration
        Platform platform = new Platform(platformId, platformInterworkingInterfaceAddress, platformInstanceFriendlyName, platformOwner, new Certificate(), new HashMap<>());
        // inject platform AAM Cert
        Certificate platformAAMCertificate = new Certificate(CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1")));
        platform.setPlatformAAMCertificate(platformAAMCertificate);
        // save the service into the repo
        platformRepository.save(platform);

        // issue smartSpace registration
        SmartSpace smartSpace = new SmartSpace(preferredSmartSpaceId, smartSpaceInstanceFriendlyName, smartSpaceGateWayAddress, isExposingSiteLocalAddress, smartSpaceSiteLocalAddress, new Certificate(), new HashMap<>(), smartSpaceOwner);
        // inject platform AAM Cert
        Certificate smartSpaceAAMCertificate = new Certificate(CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1")));
        smartSpace.setLocalCertificationAuthorityCertificate(smartSpaceAAMCertificate);
        // save the service into the repo
        smartSpaceRepository.save(smartSpace);


        Map<String, AAM> aams = aamServices.getAvailableAAMs();
        // there should be core, one platform and smart space AAM.
        assertEquals(3, aams.size());
        // verifying the contents
        //expect CoreAAM
        AAM coreAAM = aams.get(SecurityConstants.CORE_AAM_INSTANCE_ID);
        assertNotNull(coreAAM);
        assertEquals(SecurityConstants.CORE_AAM_INSTANCE_ID, coreAAM.getAamInstanceId());
        assertEquals(coreInterfaceAddress, coreAAM.getAamAddress());
        assertEquals(SecurityConstants.CORE_AAM_FRIENDLY_NAME, coreAAM.getAamInstanceFriendlyName());
        // then comes the registered platform
        assertTrue(aams.containsKey(platformId));
        AAM platformAAM = aams.get(platformId);
        assertEquals(platformId, platformAAM.getAamInstanceId());
        assertEquals(platformInterworkingInterfaceAddress + platformAAMSuffixAtInterWorkingInterface, platformAAM
                .getAamAddress());
        assertEquals(platformInstanceFriendlyName, platformAAM.getAamInstanceFriendlyName());
        assertEquals(platformAAMCertificate.getCertificateString(), platformAAM.getAamCACertificate().getCertificateString());
        assertEquals(0, platformAAM.getComponentCertificates().size());
        // and then comes the registered smartSpace
        assertTrue(aams.containsKey(preferredSmartSpaceId));
        AAM smartSpaceAAM = aams.get(preferredSmartSpaceId);
        assertEquals(preferredSmartSpaceId, smartSpaceAAM.getAamInstanceId());
        assertEquals(smartSpaceSiteLocalAddress, smartSpaceAAM.getSiteLocalAddress());
        assertEquals(smartSpaceGateWayAddress, smartSpaceAAM.getAamAddress());
        assertEquals(smartSpaceInstanceFriendlyName, smartSpaceAAM.getAamInstanceFriendlyName());
        assertEquals(smartSpaceAAMCertificate.getCertificateString(), smartSpaceAAM.getAamCACertificate().getCertificateString());
        assertEquals(0, smartSpaceAAM.getComponentCertificates().size());
    }

    @Test
    public void getAvailableAAMsByRegisteredPlatformSuccess() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            AAMException {
        //change issuing authority type
        String testplatformId = "test-PlatformId";
        doReturn(IssuingAuthorityType.PLATFORM).when(certificationAuthorityHelper).getDeploymentType();
        doReturn(testplatformId).when(certificationAuthorityHelper).getAAMInstanceIdentifier();
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");

        // injecting core component certificate
        String componentId = "registry";
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "keystores/core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);

        Map<String, AAM> aams = aamServices.getAvailableAAMs();
        assertEquals(3, aams.size());
        // verifying the contents
        assertTrue(aams.containsKey(testplatformId));
        AAM platformAAM = aams.get(testplatformId);
        // should contain one component certificate
        assertEquals(1, platformAAM.getComponentCertificates().size());
        assertEquals(componentCertificate.getCertificate().getCertificateString(), platformAAM.getComponentCertificates().get(componentId).getCertificateString());
        assertNotEquals(certificationAuthorityHelper.getAAMCert(), platformAAM.getAamCACertificate().getCertificateString());
        //platforms should have siteLocalAddress empty
        assertTrue(platformAAM.getSiteLocalAddress().isEmpty());

    }

    @Test(expected = AAMException.class)
    public void getAvailableAAMsByNotRegisteredPlatformSuccess() throws
            IOException,
            CertificateException,
            AAMException {
        //change issuing authority type
        String testplatformId = "test-PlatformId2";
        doReturn(IssuingAuthorityType.PLATFORM).when(certificationAuthorityHelper).getDeploymentType();
        doReturn(testplatformId).when(certificationAuthorityHelper).getAAMInstanceIdentifier();
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");
        aamServices.getAvailableAAMs();
    }

    @Test
    public void getAvailableAAMsByRegisteredSmartSpaceSuccess() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            AAMException {
        //change issuing authority type and instance id (still platform cause it is returned by dummy core.)
        String testSmartSpaceId = "test-PlatformId";
        doReturn(IssuingAuthorityType.SMART_SPACE).when(certificationAuthorityHelper).getDeploymentType();
        doReturn(testSmartSpaceId).when(certificationAuthorityHelper).getAAMInstanceIdentifier();
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");
        String siteLocalAddress = "siteLocalAddress";
        ReflectionTestUtils.setField(aamServices, "siteLocalAddress", siteLocalAddress);

        // injecting component certificate (no matter what cert)
        String componentId = "registry";
        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                                "keystores/core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);

        Map<String, AAM> aams = aamServices.getAvailableAAMs();
        assertEquals(3, aams.size());
        // verifying the contents
        assertTrue(aams.containsKey(testSmartSpaceId));
        AAM smartSpaceAAM = aams.get(testSmartSpaceId);
        // should contain one component certificate
        assertEquals(1, smartSpaceAAM.getComponentCertificates().size());
        assertEquals(componentCertificate.getCertificate().getCertificateString(), smartSpaceAAM.getComponentCertificates().get(componentId).getCertificateString());
        assertNotEquals(certificationAuthorityHelper.getAAMCert(), smartSpaceAAM.getAamCACertificate().getCertificateString());
        //check if siteLocalAddress was added
        assertEquals(siteLocalAddress, smartSpaceAAM.getSiteLocalAddress());


    }

    @Test(expected = AAMException.class)
    public void getAvailableAAMsByNotRegisteredSmartSpaceSuccess() throws
            IOException,
            CertificateException,
            AAMException {
        //change issuing authority type
        doReturn(IssuingAuthorityType.SMART_SPACE).when(certificationAuthorityHelper).getDeploymentType();
        doReturn(preferredSmartSpaceId).when(certificationAuthorityHelper).getAAMInstanceIdentifier();
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");
        aamServices.getAvailableAAMs();
    }
}
