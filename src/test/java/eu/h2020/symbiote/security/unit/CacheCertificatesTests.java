package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.repositories.RevokedRemoteTokensRepository;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@TestPropertySource("/cache.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class CacheCertificatesTests extends AbstractAAMTestSuite {

    @Autowired
    protected RevokedRemoteTokensRepository revokedRemoteTokensRepository;
    @Autowired
    DummyPlatformAAM dummyPlatformAAM;
    @Autowired
    AAMServices aamServices;
    @Autowired
    private DummyCoreAAM dummyCoreAAM;
    @LocalServerPort
    private int port;

    private CertificationAuthorityHelper oldCertificationAuthorityHelper;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        dummyCoreAAM.port = port;
        oldCertificationAuthorityHelper = certificationAuthorityHelper;
        dummyPlatformAAM.certificateFlag = true;
        certificationAuthorityHelper = mock(CertificationAuthorityHelper.class);
        when(certificationAuthorityHelper.getDeploymentType()).thenReturn(IssuingAuthorityType.PLATFORM);
        when(certificationAuthorityHelper.getAAMInstanceIdentifier()).thenReturn(oldCertificationAuthorityHelper.getAAMInstanceIdentifier());

        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");
        ReflectionTestUtils.setField(aamServices, "certificationAuthorityHelper", certificationAuthorityHelper);
    }

    @After
    public void after() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress);
        ReflectionTestUtils.setField(aamServices, "certificationAuthorityHelper", oldCertificationAuthorityHelper);
        dummyPlatformAAM.certificateFlag = true;
        dummyCoreAAM.initializeAvailableAAMs();
    }


    @Test
    public void getComponentCertificateCached() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            AAMException,
            TimeoutException,
            UnrecoverableKeyException,
            InvalidArgumentsException,
            InvalidAlgorithmParameterException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            InterruptedException {

        String component = aamServices.getComponentCertificate(componentId, platformId);
        dummyPlatformAAM.certificateFlag = false;
        String newComponent = aamServices.getComponentCertificate(componentId, platformId);
        assertEquals(component, newComponent);
        Thread.sleep(componentCertificateCacheExpirationTime * 1000 + 100);
        newComponent = aamServices.getComponentCertificate(componentId, platformId);
        assertNotEquals(component, newComponent);
    }

    @Test
    public void getAvailableAAMsCached() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            AAMException,
            TimeoutException,
            UnrecoverableKeyException,
            InvalidArgumentsException,
            InvalidAlgorithmParameterException,
            UserManagementException,
            PlatformManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            InterruptedException {

        Map<String, AAM> aams = aamServices.getAvailableAAMs();
        dummyCoreAAM.clearAvailablePlatformAAMs();
        Map<String, AAM> newaams = aamServices.getAvailableAAMs();
        assertEquals(aams.size(), newaams.size());
        Thread.sleep(availableAAMsCacheExpirationTime * 1000 + 100);
        newaams = aamServices.getAvailableAAMs();
        assertNotEquals(aams.size(), newaams.size());
    }
}
