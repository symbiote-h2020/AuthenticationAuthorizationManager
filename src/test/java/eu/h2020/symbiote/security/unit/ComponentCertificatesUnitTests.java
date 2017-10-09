package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.services.AAMServices;
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


@TestPropertySource("/platform.properties")
public class ComponentCertificatesUnitTests extends AbstractAAMTestSuite {

    @Autowired
    DummyPlatformAAM dummyPlatformAAM;
    @Autowired
    private DummyCoreAAM dummyCoreAAM;
    @Autowired
    AAMServices aamServices;
    @LocalServerPort
    private int port;
    @Autowired
    private ComponentCertificatesRepository componentCertificatesRepository;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        dummyCoreAAM.port = port;
    }

    @Test
    public void getLocalComponentCertificateOtherPlatformSuccess() throws NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException, KeyStoreException, IOException, AAMException, TimeoutException, UnrecoverableKeyException, InvalidArgumentsException, InvalidAlgorithmParameterException, UserManagementException, PlatformManagementException, WrongCredentialsException, NotExistingUserException, ValidationException {

        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress + "/test/caam");
        String component = aamServices.getComponentCertificate("componentId", "test-PlatformId");

        assertTrue(component.contains("BEGIN CERTIFICATE"));

    }

    @Test
    public void getLocalComponentCertificateNonExistingOtherPlatform() throws CertificateException, AAMException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidArgumentsException, IOException {

        expectedEx.expect(AAMException.class);
        expectedEx.expectMessage("Selected certificate could not be found/retrieved");

        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress + "/test/caam");
        aamServices.getComponentCertificate("componentId", "non-existing-PlatformId");

    }

    @Test
    public void getLocalComponentCertificateSamePlatformNonExistingComponent() throws CertificateException, AAMException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidArgumentsException, IOException {

        expectedEx.expect(InvalidArgumentsException.class);
        expectedEx.expectMessage("Component doesn't exist in this platform");

        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress + "/test/caam");
        aamServices.getComponentCertificate("componentId", "platform-1");

    }

    @Test
    public void getLocalComponentCertificateSamePlatformSuccess() throws CertificateException, AAMException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidArgumentsException, IOException {

        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress + "/test/caam");

        ComponentCertificate componentCertificate = new ComponentCertificate(
                componentId,
                new Certificate(
                        CryptoHelper.convertX509ToPEM(DummyPlatformAAM.getCertificateFromTestKeystore(
                                "core.p12",
                                "registry-core-1"))));
        componentCertificatesRepository.save(
                componentCertificate);

        String component = aamServices.getComponentCertificate("componentId", "platform-1");
        assertTrue(component.contains("BEGIN CERTIFICATE"));

    }

    @Test
    public void getLocalComponentCertificateSamePlatformCoreSucces() throws CertificateException, AAMException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidArgumentsException, IOException {

        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress + "/test/caam");

        String component = aamServices.getComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME, "platform-1");
        assertTrue(component.contains("BEGIN CERTIFICATE"));

    }



}
