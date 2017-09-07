package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.helpers.PlatformAAMCertificateKeyStoreFactory;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;
import static org.hibernate.validator.internal.util.Contracts.assertNotNull;

@TestPropertySource("/core.properties")
public class PlatformCertificateKeyStoreTests extends AbstractAAMTestSuite {
    private final String KEY_STORE_PATH = "./src/test/resources/new.p12";
    private final String KEY_STORE_PASSWORD = "1234567";


    @Test
    public void PlatformCertificateKeyStoreSuccess() throws IOException, CertificateException, NoSuchAlgorithmException, ValidationException, KeyStoreException, InvalidArgumentsException, InvalidAlgorithmParameterException, NotExistingUserException, WrongCredentialsException, NoSuchProviderException {
        //platformOwner and platform  registration
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, "", "", platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        Map<String, Platform> platforms = new HashMap<>();
        platforms.put(platformId, platform);
        platformOwner.setOwnedPlatforms(platforms);

        PlatformAAMCertificateKeyStoreFactory.getPlatformAAMKeystore(
                serverAddress, platformOwnerUsername, platformOwnerPassword, platformId, KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                "root_cert", "aam_cert", PV_KEY_PASSWORD
        );
        //keyStore checking if proper Certificates exists
        KeyStore trustStore = KeyStore.getInstance("JKS");
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

}
