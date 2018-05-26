package eu.h2020.symbiote.security.unit.credentialsvalidation;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM2;
import eu.h2020.symbiote.security.utils.DummyPlatformAAMRevokedIPK;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;

import static eu.h2020.symbiote.security.services.helpers.TokenIssuer.buildAuthorizationToken;
import static org.junit.Assert.*;

/**
 * Test suite for generic AAM functionality - deployment type Platform
 *
 * @author Piotr Kicki (PSNC)
 */
@TestPropertySource("/platform.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class CredentialsValidationInPlatformAAMUnitTests extends
        AbstractAAMTestSuite {

    @Autowired
    private ValidationHelper validationHelper;
    @Autowired
    private TokenIssuer tokenIssuer;
    @Autowired
    private AAMServices aamServices;
    @Autowired
    private DummyCoreAAM dummyCoreAAM;
    @Autowired
    private DummyPlatformAAMRevokedIPK dummyPlatformAAMRevokedIPK;
    @Autowired
    private DummyPlatformAAM2 dummyPlatformAAM2;



    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        //setting dummyCoreAAM to return basic set of Platform AAMs
        dummyCoreAAM.initializeAvailableAAMs();
        // fixing the core AAM url to point to the dummyCoreAAM
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");
        ReflectionTestUtils.setField(validationHelper, "coreInterfaceAddress", serverAddress + "/test/caam");
        ReflectionTestUtils.setField(aamServices, "interworkingInterface", serverAddress);
    }

    @After
    public void after() {
        // fixing the core AAM url to point back to the service
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress);
        ReflectionTestUtils.setField(validationHelper, "coreInterfaceAddress", serverAddress);
        ReflectionTestUtils.setField(validationHelper, "isOfflineEnough", false);
    }

    @Test
    public void validateValidPlatform() throws
            SecurityException,
            CertificateException {

        // prepare the user in db
        addTestUserWithClientCertificateToRepository();
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.VALID, response);
    }

    @Test
    public void validateRevokedIPK() throws
            ValidationException,
            MalformedJWTException,
            IOException,
            ClassNotFoundException {
        // issuing dummy platform token from platform with revoked certificate
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAMRevokedIPK.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateIssuerDiffersDeploymentIdAndNotInAvailableAAMs() throws
            ValidationException,
            MalformedJWTException,
            IOException,
            ClassNotFoundException {
        // issuing dummy platform token from unregistered platform
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAM2.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateExpiredSubjectCertificate() throws
            SecurityException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {
        // prepare the user in db
        userRepository.save(new User(username, passwordEncoder.encode(password), "", new HashMap<>(), UserRole.USER, AccountStatus.NEW, new HashMap<>(), new HashSet<>(), true, false));
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // injection of expired certificate
        X509Certificate cert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-exp-c1");
        Certificate certificate = new Certificate(CryptoHelper.convertX509ToPEM(cert));
        user.getClientCertificates().put(clientId, certificate);
        userRepository.save(user);

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, cert.getPublicKey());

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.EXPIRED_SUBJECT_CERTIFICATE, response);
    }

    @Test
    public void validateRemoteTokenWhichHasIssuerCertificateDifferentFromTheOneFetchedFromCoreAAM() throws
            ValidationException,
            MalformedJWTException {
        // acquiring valid token from an AAM that is malicious
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyCoreAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateOfflineCoreAAMSuccess() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            UnrecoverableKeyException,
            ValidationException,
            AAMException {
        //setting wrong core AAM url to make it offline
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", "wrong AAM url");
        ReflectionTestUtils.setField(validationHelper, "isOfflineEnough", true);
        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000L,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyTestFromKeystore("keystores/platform_1.p12", "platform-1-1-c1")
        );

        // valid remote home token chain
        assertEquals(
                ValidationStatus.VALID,
                validationHelper.validateRemotelyIssuedToken(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }

    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateOfflineIssuerAAMSuccess() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            UnrecoverableKeyException,
            ValidationException,
            AAMException {

        ReflectionTestUtils.setField(validationHelper, "isOfflineEnough", true);

        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000L,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyTestFromKeystore("keystores/platform_1.p12", "platform-1-1-c1")
        );

        // valid remote home token chain
        assertEquals(
                ValidationStatus.VALID,
                validationHelper.validateRemotelyIssuedToken(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }

    @Test
    public void validateRemoteForeignTokenRequestUsingCertificateOfflineCoreAAMSuccess() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            UnrecoverableKeyException {
        //setting wrong core AAM url to make it offline
        ReflectionTestUtils.setField(validationHelper, "coreInterfaceAddress", "wrong AAM url");
        ReflectionTestUtils.setField(validationHelper, "isOfflineEnough", true);
        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        X509Certificate tokenIssuerAAMCert = getCertificateFromTestKeystore("keystores/platform_2.p12", "platform-2-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId@platform-1",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.FOREIGN,
                100000L,
                "platform-2",
                tokenIssuerAAMCert.getPublicKey(),
                getPrivateKeyTestFromKeystore("keystores/platform_2.p12", "platform-2-1-c1")
        );

        // valid remote foreign token chain
        assertEquals(
                ValidationStatus.VALID,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        CryptoHelper.convertX509ToPEM(tokenIssuerAAMCert))
        );

        // just for foreignTokenIssuerCert check check
        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        certificationAuthorityHelper.getRootCACert())
        );

    }

    @Test
    public void validateRemoteForeignTokenRequestUsingCertificateOfflineIssuerAAMSuccess() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            UnrecoverableKeyException {

        ReflectionTestUtils.setField(validationHelper, "isOfflineEnough", true);

        //set dummy Core AAM to return valid platform 2 certificate
        dummyCoreAAM.addPlatform2Certificate();
        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        X509Certificate tokenIssuerAAMCert = getCertificateFromTestKeystore("keystores/platform_2.p12", "platform-2-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId@platform-1",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.FOREIGN,
                100000L,
                "platform-2",
                tokenIssuerAAMCert.getPublicKey(),
                getPrivateKeyTestFromKeystore("keystores/platform_2.p12", "platform-2-1-c1")
        );

        // valid remote foreign token chain
        assertEquals(
                ValidationStatus.VALID,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        CryptoHelper.convertX509ToPEM(tokenIssuerAAMCert))
        );

        // just for foreignTokenIssuerCert check check
        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        certificationAuthorityHelper.getRootCACert())
        );

    }
}