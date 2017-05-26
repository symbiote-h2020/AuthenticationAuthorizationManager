package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AuthenticationAuthorizationManagerTests;
import eu.h2020.symbiote.security.commons.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.commons.TokenManager;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.AAMException;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.payloads.*;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for generic AAM functionality irrelevant to actual deployment type (Core or Platform)
 */
@TestPropertySource("/core.properties")
public class CommonAuthenticationAuthorizationManagerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CommonAuthenticationAuthorizationManagerTests.class);

    @Autowired
    private TokenManager tokenManager;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    /**
     * Feature: User Repository
     */
    @Test
    public void applicationInternalRegistrationSuccess() throws AAMException {
        String appUsername = "NewApplication";

        // verify that app is not in the repository
        User registeredUser = userRepository.findOne(appUsername);
        assertNull(registeredUser);

            /*
             XXX federated Id and recovery mail are required for Test & Core AAM but not for Platform AAM
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
        //assertFalse(registeredUser.getCertificate().getX509().getExtensionValue(new ASN1ObjectIdentifier
        // ("2.5.29.19"),));
    }


    /**
     * Feature: User Repository
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationInternalUnregistrationSuccess() throws AAMException, CertificateException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // unregister the user
        userRegistrationService.unregister(username);
        log.debug("User successfully unregistered!");

        // verify that app is not anymore in the repository
        assertFalse(userRepository.exists(username));

        // verify that the user certificate was indeed revoked
        assertTrue(revokedKeysRepository.exists(username));
        SubjectsRevokedKeys revokedKeys = revokedKeysRepository.findOne(username);
        assertNotNull(revokedKeys);
        assertTrue(revokedKeys.getRevokedKeysSet().contains(user.getCertificate().getX509().getPublicKey().toString()));
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
    public void checkRevocationWrongToken() throws AAMException, CertificateException, SecurityHandlerException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        //check if home token revoked properly
        CheckRevocationResponse response = tokenManager.checkHomeTokenRevocation("tokenString");
        assertEquals(ValidationStatus.INVALID, ValidationStatus.valueOf(response.getStatus()));
    }

    @Test
    public void checkRevocationExpiredToken() throws AAMException, CertificateException, SecurityHandlerException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenManager.createHomeToken(user);

        //Introduce latency so that JWT expires
        try {
            Thread.sleep(tokenValidityPeriod + 1000);
        } catch (InterruptedException e) {
            log.error(e);
        }

        //check if home token revoked properly
        CheckRevocationResponse response = tokenManager.checkHomeTokenRevocation(homeToken.getToken());
        assertEquals(ValidationStatus.EXPIRED, ValidationStatus.valueOf(response.getStatus()));
    }

    @Test
    public void checkRevocationAfterUnregistration() throws AAMException, CertificateException, SecurityHandlerException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenManager.createHomeToken(user);

        // unregister the user
        userRegistrationService.unregister(username);
        //log.debug("User successfully unregistered!");

        //check if home token revoked properly
        CheckRevocationResponse response = tokenManager.checkHomeTokenRevocation(homeToken.getToken());
        assertEquals(ValidationStatus.REVOKED, ValidationStatus.valueOf(response.getStatus()));
    }

    @Test
    public void checkRevocationRevokedToken() throws AAMException, CertificateException, SecurityHandlerException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenManager.createHomeToken(user);

        //add token to repository
        revokedTokensRepository.save(homeToken);

        //check if home token revoked properly
        CheckRevocationResponse response = tokenManager.checkHomeTokenRevocation(homeToken.getToken());
        assertEquals(ValidationStatus.REVOKED, ValidationStatus.valueOf(response.getStatus()));
    }

    @Test
    public void checkRevocationRevokedIPK() throws AAMException, CertificateException, SecurityHandlerException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenManager.createHomeToken(user);
        String issuer = JWTEngine.getClaims(homeToken.getToken()).getIssuer();
        Set<String> keySet = new HashSet<>();
        keySet.add(user.getCertificate().getX509().getPublicKey().toString());

        //adding key to revoked repository
        SubjectsRevokedKeys subjectsRevokedKeys = new SubjectsRevokedKeys(issuer, keySet);
        revokedKeysRepository.save(subjectsRevokedKeys);

        //check if home token revoked properly
        CheckRevocationResponse response = tokenManager.checkHomeTokenRevocation(homeToken.getToken());
        assertEquals(ValidationStatus.REVOKED, ValidationStatus.valueOf(response.getStatus()));
    }
}