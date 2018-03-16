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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@TestPropertySource("/core.properties")
public class GetComponentCertificateUnitTests extends AbstractAAMTestSuite {

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
        when(certificationAuthorityHelper.getRootCACertificate()).thenReturn(oldCertificationAuthorityHelper.getRootCACertificate());
        when(certificationAuthorityHelper.getRootCACert()).thenReturn(oldCertificationAuthorityHelper.getRootCACert());
        when(certificationAuthorityHelper.isServiceCertificateChainTrusted(anyString())).thenReturn(true);

        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");
        ReflectionTestUtils.setField(aamServices, "certificationAuthorityHelper", certificationAuthorityHelper);
    }

    @After
    public void after() {
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress);
        ReflectionTestUtils.setField(aamServices, "certificationAuthorityHelper", oldCertificationAuthorityHelper);
        dummyPlatformAAM.certificateFlag = 1;

    }

    @Test
    public void getLocalComponentCertificateOtherPlatformSuccess() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            IOException,
            AAMException,
            InvalidArgumentsException {

        //dirty hack to pass TrustChain of the certificate. (client cert is returned)
        dummyPlatformAAM.certificateFlag = 2;
        String component = aamServices.getComponentCertificate(componentId, platformId);

        assertTrue(component.contains("BEGIN CERTIFICATE"));

    }

    @Test
    public void getLocalComponentCertificateOtherPlatformFailWrongTrustChain() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            IOException,
            InvalidArgumentsException {
        try {
            //dummy platform returns core component certificate, not its own
            aamServices.getComponentCertificate(componentId, platformId);
        } catch (AAMException e) {
            assertEquals(AAMException.REMOTE_AAMS_COMPONENT_CERTIFICATE_IS_NOT_TRUSTED, e.getMessage());
        }
    }

    @Test
    public void getLocalComponentCertificateNonExistingOtherPlatform() throws
            CertificateException,
            AAMException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidArgumentsException,
            IOException {

        expectedEx.expect(AAMException.class);
        expectedEx.expectMessage("Selected certificate could not be found/retrieved");

        aamServices.getComponentCertificate(componentId, "non-existing-PlatformId");

    }

    @Test
    public void getCoreCertificateFromKeystoreForImitatedPAAM() throws
            CertificateException,
            AAMException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidArgumentsException,
            IOException {
        //setting AAM instance Identifier different than Core AAM and recognizable RootCaCert
        when(certificationAuthorityHelper.getAAMInstanceIdentifier()).thenReturn("newTestPlatform");
        when(certificationAuthorityHelper.getRootCACert()).thenReturn("Keystore Root Cert");
        when(certificationAuthorityHelper.getAAMCert()).thenReturn("Just some dummy");
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", "wrong adress");
        ReflectionTestUtils.setField(aamServices, "certificationAuthorityHelper", certificationAuthorityHelper);

        String coreCertificate = aamServices.getComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME, SecurityConstants.CORE_AAM_INSTANCE_ID);
        //check if returned mocked value
        assertTrue(coreCertificate.contains("Keystore Root Cert"));
    }

}
