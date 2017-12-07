package eu.h2020.symbiote.security.unit.credentialsvalidation;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.concurrent.TimeoutException;

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



    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        //setting dummyCoreAAM to return basic set of Platform AAMs
        dummyCoreAAM.initializeAvailableAAMs();
        // fixing the core AAM url to point to the dummyCoreAAM
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");
    }

    @After
    public void after() throws Exception {
        // fixing the core AAM url to point to the dummyCoreAAM
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");
    }

    @Test
    public void validateValidPlatform() throws SecurityException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, TimeoutException, UnrecoverableKeyException, OperatorCreationException, InvalidKeyException {

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
    public void validateRevokedIPK() throws IOException, ValidationException, JWTCreationException {
        // issuing dummy platform token from platform with revoked certificate
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/rev_ipk/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateIssuerDiffersDeploymentIdAndNotInAvailableAAMs() throws IOException, ValidationException, JWTCreationException {
        // issuing dummy platform token from unregistered platform
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/second/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateExpiredSubjectCertificate() throws SecurityException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, TimeoutException, InvalidAlgorithmParameterException, UnrecoverableKeyException, OperatorCreationException {
        // prepare the user in db
        userRepository.save(new User(username, passwordEncoder.encode(password), "", new HashMap<>(), UserRole.USER, new HashMap<>(), new HashSet<>()));
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // injection of expired certificate
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/platform_1.p12"), "1234567".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate("platform-1-1-exp-c1");
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
    public void validateIssuerDiffersDeploymentIdAndInAvailableAAMsButRevoked() throws IOException, ValidationException, JWTCreationException {
        // issuing dummy platform token
        // acquiring valid token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/caam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.REVOKED_IPK, response);
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
        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        //X509Certificate wrongAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-2-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_1.p12", "platform-1-1-c1")
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

        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        //X509Certificate wrongAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-2-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_1.p12", "platform-1-1-c1")
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
            ValidationException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException, UnrecoverableKeyException {
        //setting wrong core AAM url to make it offline
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", "wrong AAM url");
        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        X509Certificate tokenIssuerAAMCert = getCertificateFromTestKeystore("platform_2.p12", "platform-2-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId@platform-1",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.FOREIGN,
                100000l,
                "platform-2",
                tokenIssuerAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_2.p12", "platform-2-1-c1")
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
            ValidationException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException, UnrecoverableKeyException {
        //set dummy Core AAM to return valid platform 2 certificate
        dummyCoreAAM.addPlatform2Certificate();
        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        X509Certificate tokenIssuerAAMCert = getCertificateFromTestKeystore("platform_2.p12", "platform-2-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId@platform-1",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.FOREIGN,
                100000l,
                "platform-2",
                tokenIssuerAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_2.p12", "platform-2-1-c1")
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