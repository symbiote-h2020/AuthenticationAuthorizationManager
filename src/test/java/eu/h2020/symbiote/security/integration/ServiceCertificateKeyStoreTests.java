package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.helpers.PlatformAAMCertificateKeyStoreFactory;
import eu.h2020.symbiote.security.helpers.SmartSpaceAAMCertificateKeyStoreFactory;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;

import static junit.framework.TestCase.assertTrue;
import static org.hibernate.validator.internal.util.Contracts.assertNotNull;

@TestPropertySource("/core.properties")
public class ServiceCertificateKeyStoreTests extends AbstractAAMTestSuite {
    private final String KEY_STORE_PATH = "./src/test/resources/keystores/new.p12";
    private final String KEY_STORE_PASSWORD = "1234567";


    @Test
    public void PlatformCertificateKeyStoreSuccess() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            ValidationException,
            KeyStoreException,
            InvalidArgumentsException,
            InvalidAlgorithmParameterException,
            NotExistingUserException,
            NoSuchProviderException,
            AAMException {
        //platformOwner and platform  registration
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, "", "", platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedServices().add(platformId);
        userRepository.save(platformOwner);

        PlatformAAMCertificateKeyStoreFactory.getServiceAAMKeystore(
                serverAddress,
                platformOwnerUsername,
                platformOwnerPassword,
                platformId,
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                "root_cert",
                "aam_cert",
                LogFactory.getLog(PlatformAAMCertificateKeyStoreFactory.class)
        );
        //keyStore checking if proper Certificates exists
        KeyStore trustStore = KeyStore.getInstance("PKCS12", "BC");
        try (
                FileInputStream fIn = new FileInputStream(KEY_STORE_PATH)) {
            trustStore.load(fIn, KEY_STORE_PASSWORD.toCharArray());
            fIn.close();
            assertNotNull(trustStore.getCertificate("root_cert"));
            assertNotNull(trustStore.getCertificate("aam_cert"));
        }
        //cleanup
        File file = new File(KEY_STORE_PATH);
        assertTrue(file.delete());
    }

    @Test
    public void SmartSpaceCertificateKeyStoreSuccess() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            ValidationException,
            KeyStoreException,
            InvalidArgumentsException,
            InvalidAlgorithmParameterException,
            NotExistingUserException,
            NoSuchProviderException,
            AAMException {
        //smart space Owner and Smart Space  registration
        User smartSpaceOwner = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        SmartSpace smartSpace = new SmartSpace(preferredSmartSpaceId,
                smartSpaceGateWayAddress,
                smartSpaceSiteLocalAddress,
                exposedIIAddress,
                smartSpaceInstanceFriendlyName,
                new Certificate(),
                new HashMap<>(),
                smartSpaceOwner);
        smartSpaceRepository.save(smartSpace);
        smartSpaceOwner.getOwnedServices().add(preferredSmartSpaceId);
        userRepository.save(smartSpaceOwner);

        SmartSpaceAAMCertificateKeyStoreFactory.getServiceAAMKeystore(
                serverAddress,
                smartSpaceOwnerUsername,
                smartSpaceOwnerPassword,
                preferredSmartSpaceId,
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                "root_cert",
                "aam_cert",
                LogFactory.getLog(SmartSpaceAAMCertificateKeyStoreFactory.class)
        );
        //keyStore checking if proper Certificates exists
        KeyStore trustStore = KeyStore.getInstance("PKCS12", "BC");
        try (
                FileInputStream fIn = new FileInputStream(KEY_STORE_PATH)) {
            trustStore.load(fIn, KEY_STORE_PASSWORD.toCharArray());
            fIn.close();
            assertNotNull(trustStore.getCertificate("root_cert"));
            assertNotNull(trustStore.getCertificate("aam_cert"));
        }
        //cleanup
        // File file = new File(KEY_STORE_PATH);
        // assertTrue(file.delete());
    }

}
