package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@TestPropertySource("/core.properties")
public class ComponentCertificatesUnitTests extends AbstractAAMTestSuite {

    @Autowired
    DummyPlatformAAM dummyPlatformAAM;
    @Autowired
    private DummyCoreAAM dummyCoreAAM;
    @Autowired
    AAMServices aamServices;
    @LocalServerPort
    private int port;
    private CertificationAuthorityHelper oldCertificationAuthorityHelper;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        dummyCoreAAM.port = port;
        oldCertificationAuthorityHelper = certificationAuthorityHelper;
        certificationAuthorityHelper = mock(CertificationAuthorityHelper.class);
        when(certificationAuthorityHelper.getDeploymentType()).thenReturn(IssuingAuthorityType.PLATFORM);
        when(certificationAuthorityHelper.getAAMInstanceIdentifier()).thenReturn(oldCertificationAuthorityHelper.getAAMInstanceIdentifier());

        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");
        ReflectionTestUtils.setField(aamServices, "certificationAuthorityHelper", certificationAuthorityHelper);
    }

    @After
    public void after() {
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress);
        ReflectionTestUtils.setField(aamServices, "certificationAuthorityHelper", oldCertificationAuthorityHelper);

    }

    @Test
    public void getLocalComponentCertificateOtherPlatformSuccess() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            AAMException,
            InvalidArgumentsException {

        String component = aamServices.getComponentCertificate(componentId, platformId);

        assertTrue(component.contains("BEGIN CERTIFICATE"));

    }

    @Test
    public void getLocalComponentCertificateNonExistingOtherPlatform() throws
            CertificateException,
            AAMException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            InvalidArgumentsException,
            IOException {

        expectedEx.expect(AAMException.class);
        expectedEx.expectMessage("Selected certificate could not be found/retrieved");

        aamServices.getComponentCertificate(componentId, "non-existing-PlatformId");

    }

    @Test
    public void getCoreCertificateFromKeystore() throws
            CertificateException,
            AAMException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            InvalidArgumentsException,
            IOException {
        //setting AAM instance Identifier different than Core AAM and recognizable RootCaCert
        when(certificationAuthorityHelper.getAAMInstanceIdentifier()).thenReturn("newTestPlatform");
        when(certificationAuthorityHelper.getRootCACert()).thenReturn("Keystore Root Cert");
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", "wrong adress");
        ReflectionTestUtils.setField(aamServices, "certificationAuthorityHelper", certificationAuthorityHelper);

        String coreCertificate = aamServices.getComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME, SecurityConstants.CORE_AAM_INSTANCE_ID);
        //check if returned mocked value
        assertTrue(coreCertificate.contains("Keystore Root Cert"));
    }

}
