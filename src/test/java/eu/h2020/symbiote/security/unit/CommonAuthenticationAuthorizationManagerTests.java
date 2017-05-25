package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AuthenticationAuthorizationManagerTests;
import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.aam.ExistingUserException;
import eu.h2020.symbiote.security.exceptions.aam.NotExistingUserException;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.payloads.UserDetails;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import eu.h2020.symbiote.security.payloads.UserRegistrationResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for generic AAM functionality irrelevant to actual deployment type (Core or Platform)
 */
@TestPropertySource("/core.properties")
public class CommonAuthenticationAuthorizationManagerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CommonAuthenticationAuthorizationManagerTests.class);

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    /**
     * Feature: User Repository
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationInternalRegistrationSuccess() throws Exception {
        try {
            String appUsername = "NewApplication";

            // verify that app is not in the repository
            User registeredUser = userRepository.findOne(appUsername);
            assertNull(registeredUser);

            /*
             XXX federated Id and recovery mail are required for Test & Core AAM but not for Plaftorm AAM
             */
            // register new application to db
            UserRegistrationRequest userRegistrationRequest = new UserRegistrationRequest(new
                    Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials
                    (appUsername, "NewPassword"), "nullId", "nullMail", UserRole.APPLICATION));
            UserRegistrationResponse userRegistrationResponse = userRegistrationService.register
                    (userRegistrationRequest);

            // verify that app really is in repository
            registeredUser = userRepository.findOne(appUsername);
            assertNotNull(registeredUser);
            assertEquals(UserRole.APPLICATION, registeredUser.getRole());

            // verify that the server returns certificate & privateKey
            assertNotNull(userRegistrationResponse.getUserCertificate());
            assertNotNull(userRegistrationResponse.getUserPrivateKey());

            // TODO verify that released certificate has no CA property
        } catch (Exception e) {
            assertEquals(ExistingUserException.class, e.getClass());
            log.info(e.getMessage());
        }
    }


    /**
     * Feature: User Repository
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationInternalUnregistrationSuccess() throws Exception {
        try {
            // verify that app really is in repository
            User user = userRepository.findOne(username);
            assertNotNull(user);

            // get user certficate
            Certificate userCertificate = user.getCertificate();
            // verify the certificate is not yet revoked
            assertFalse(revokedCertificatesRepository.exists(userCertificate.toString()));

            // unregister
            userRegistrationService.unregister(username);
            log.debug("User successfully unregistered!");

            // verify that app is not anymore in the repository
            assertFalse(userRepository.exists(username));
            // verify that the user certificate was indeed revoked
            assertTrue(revokedCertificatesRepository.exists(userCertificate.toString()));
        } catch (Exception e) {
            assertEquals(NotExistingUserException.class, e.getClass());
            log.error(e.getMessage());
        }
    }

    /**
     * Feature:
     * Interface: PAAM - 3a
     * CommunicationType REST
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void certificateCreationAndVerification() throws Exception {
        // Generate certificate for given application username (ie. "Daniele")
        KeyPair keyPair = registrationManager.createKeyPair();
        X509Certificate cert = registrationManager.createECCert("Daniele", keyPair.getPublic());

        // retrieves Platform AAM ("Daniele"'s certificate issuer) public key from keystore in order to verify
        // "Daniele"'s certificate
        cert.verify(registrationManager.getAAMPublicKey());

        // also check time validity
        cert.checkValidity(new Date());
    }




    @Test
    public void generateCertificateFromCSRSuccess() throws OperatorCreationException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        KeyPairGenerator g = KeyPairGenerator.getInstance(KEY_PAIR_GEN_ALGORITHM, PROVIDER_NAME);
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(CURVE_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = g.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        X509Certificate cert = registrationManager.generateCertificateFromCSR(csr);
        assertNotNull(cert);
        assertEquals(new X500Name(cert.getSubjectDN().getName()),csr.getSubject());
    }
}