package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;

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

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        dummyCoreAAM.port = port;

        CertificationAuthorityHelper oldCertificationAuthorityHelper = certificationAuthorityHelper;
        certificationAuthorityHelper = mock(CertificationAuthorityHelper.class);
        when(certificationAuthorityHelper.getDeploymentType()).thenReturn(IssuingAuthorityType.PLATFORM);
        when(certificationAuthorityHelper.getAAMInstanceIdentifier()).thenReturn(oldCertificationAuthorityHelper.getAAMInstanceIdentifier());

        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress + "/test/caam");
        ReflectionTestUtils.setField(aamServices, "certificationAuthorityHelper", certificationAuthorityHelper);
    }

    @Test
    public void getLocalComponentCertificateOtherPlatformSuccess() throws NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException, KeyStoreException, IOException, AAMException, TimeoutException, UnrecoverableKeyException, InvalidArgumentsException, InvalidAlgorithmParameterException, UserManagementException, PlatformManagementException, WrongCredentialsException, NotExistingUserException, ValidationException {

        String component = aamServices.getComponentCertificate("componentId", "test-PlatformId");

        assertTrue(component.contains("BEGIN CERTIFICATE"));

    }

    @Test
    public void getLocalComponentCertificateNonExistingOtherPlatform() throws CertificateException, AAMException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidArgumentsException, IOException {

        expectedEx.expect(AAMException.class);
        expectedEx.expectMessage("Selected certificate could not be found/retrieved");

        aamServices.getComponentCertificate("componentId", "non-existing-PlatformId");

    }

}
