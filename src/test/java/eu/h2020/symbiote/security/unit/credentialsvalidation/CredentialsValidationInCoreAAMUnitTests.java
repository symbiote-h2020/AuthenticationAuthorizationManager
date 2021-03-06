package eu.h2020.symbiote.security.unit.credentialsvalidation;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.SignCertificateRequestService;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAMConnectionProblem;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.Before;
import org.junit.Test;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.FIELDS_DELIMITER;
import static eu.h2020.symbiote.security.services.helpers.TokenIssuer.buildAuthorizationToken;
import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class CredentialsValidationInCoreAAMUnitTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(CredentialsValidationInCoreAAMUnitTests.class);
    private static SecureRandom random = new SecureRandom();
    @Autowired
    private ValidationHelper validationHelper;
    @Autowired
    private TokenIssuer tokenIssuer;
    @Autowired
    private DummyPlatformAAM dummyPlatformAAM;
    @Autowired
    private DummyCoreAAM dummyCoreAAM;
    @Autowired
    private DummyPlatformAAMConnectionProblem dummyPlatformAAMConnectionProblem;
    @Autowired
    private SignCertificateRequestService signCertificateRequestService;
    @Autowired
    RabbitTemplate rabbitTemplate;
    private RestTemplate restTemplate = new RestTemplate();

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        // platform registration useful
        addTestUserWithClientCertificateToRepository();
    }

    @Test
    public void validateValidToken() throws
            SecurityException,
            CertificateException {
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
    public void validateWrongToken() {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        //check if home token is valid
        ValidationStatus response = validationHelper.validate("tokenString", "", "", "");
        assertEquals(ValidationStatus.UNKNOWN, response);
    }

    @Test
    public void validateExpiredToken() throws
            SecurityException,
            CertificateException,
            InterruptedException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());

        //Introduce latency so that JWT expires
        Thread.sleep(tokenValidityPeriod + 10);

        //check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.EXPIRED_TOKEN, response);
    }

    @Test
    public void validateTokenRevokedKey() throws
            JWTCreationException,
            CertificateException {

        // verify that user really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());

        SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(username);
        Set<String> keySet = (subjectsRevokedKeys == null) ? new HashSet<>() : subjectsRevokedKeys
                .getRevokedKeysSet();
        keySet.add(Base64.getEncoder().encodeToString(
                userKeyPair.getPublic().getEncoded()));
        // adding key to revoked repository
        revokedKeysRepository.save(new SubjectsRevokedKeys(username, keySet));

        assertNotNull(revokedKeysRepository.findOne(username));

        ValidationStatus status = validationHelper.validate(homeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.REVOKED_SPK, status);
    }

    @Test
    public void validateAfterUnregistrationBySPK() throws
            SecurityException,
            CertificateException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());

        // delete the user
        UserManagementRequest userManagementRequest = new UserManagementRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new Credentials(username, password),
                new UserDetails(new Credentials(username, password),
                        recoveryMail,
                        UserRole.USER,
                        AccountStatus.NEW, new HashMap<>(),
                        new HashMap<>(),
                        true,
                        false),
                OperationType.DELETE);
        usersManagementService.authManage(userManagementRequest);

        //check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.REVOKED_SPK, response);
    }

    @Test
    public void validateRevokedToken() throws
            SecurityException,
            CertificateException {
        // verify that app really is in repository
        User user = userRepository.findOne(username);
        assertNotNull(user);

        // verify the user keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(username));

        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(user, clientId, user.getClientCertificates().get(clientId).getX509().getPublicKey());

        // add token to revoked tokens repository
        revokedTokensRepository.save(homeToken);

        // check if home token is valid
        ValidationStatus response = validationHelper.validate(homeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.REVOKED_TOKEN, response);
    }

    @Test
    public void validateIssuerDiffersAndValidationIsRelayed() throws
            IOException,
            ValidationException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);

        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        //save platform into repo
        String platformId = "platform-1";
        User platformOwner = savePlatformOwner();
        X509Certificate certificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        String dummyPlatformAAMPEMCertString = CryptoHelper.convertX509ToPEM(certificate);
        Platform dummyPlatform = new Platform(platformId,
                serverAddress + "/test",
                platformInstanceFriendlyName,
                platformOwner,
                new Certificate(dummyPlatformAAMPEMCertString),
                new HashMap<>());
        //put any valid certificate as client cert to pass validation
        dummyPlatform.getComponentCertificates().put(clientId, new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // check if validation will be relayed to appropriate issuer
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.VALID, response);
    }

    @Test
    public void validateRevokedDummyCorePK() throws
            IOException,
            ValidationException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyCoreAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "core-2";
        //inject platform PEM Certificate to the database
        X509Certificate certificate = getCertificateFromTestKeystore("keystores/core.p12", platformId);
        String dummyPlatformAAMPEMCertString = CryptoHelper.convertX509ToPEM(certificate);

        String issuer = JWTEngine.getClaims(dummyHomeToken.getToken()).getIssuer();

        // verify the issuer keys are not yet revoked
        assertFalse(revokedKeysRepository.exists(issuer));

        // insert DummyPlatformAAM public key into set to be revoked
        Set<String> keySet = new HashSet<>();
        keySet.add(Base64.getEncoder().encodeToString(
                CryptoHelper.convertPEMToX509(dummyPlatformAAMPEMCertString).getPublicKey().getEncoded()));

        // adding key to revoked repository
        SubjectsRevokedKeys subjectsRevokedKeys = new SubjectsRevokedKeys(issuer, keySet);
        revokedKeysRepository.save(subjectsRevokedKeys);

        // check if platform token is valid
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateTokenFromDummyCoreByCore() throws
            IOException,
            ValidationException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyCoreAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "core-2";
        //inject platform PEM Certificate to the database
        X509Certificate certificate = getCertificateFromTestKeystore("keystores/platform_1.p12", platformId);
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();

        // check if platform token is valid
        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateForeignTokenIssuerNotInAvailableAAMs() throws
            IOException,
            ValidationException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            MalformedJWTException,
            AAMException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // check if home token is valid
        ValidationStatus response = validationHelper.validateRemotelyIssuedToken(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, response);
    }

    @Test
    public void validateForeignTokenPlatformRemovedFromFederation() throws
            IOException,
            ValidationException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            MalformedJWTException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        User platformOwner = savePlatformOwner();
        //inject dummy platform with platform PEM Certificate to the database
        X509Certificate certificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        String dummyPlatformAAMPEMCertString = CryptoHelper.convertX509ToPEM(certificate);
        Platform dummyPlatform = new Platform("platform-1",
                serverAddress + "/test",
                platformInstanceFriendlyName,
                platformOwner,
                new Certificate(dummyPlatformAAMPEMCertString),
                new HashMap<>());
        //put any valid certificate as client cert to pass validation
        dummyPlatform.getComponentCertificates().put(clientId, new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // adding a federation
        List<FederationMember> platformsId = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId(dummyPlatform.getPlatformInstanceId());
        platformsId.add(federationMember);

        Federation federation = new Federation();
        federation.setMembers(platformsId);
        federation.setId("federationId");

        federationsRepository.save(federation);


        Token foreignToken = null;
        try {
            foreignToken = tokenIssuer.getForeignToken(dummyHomeToken);
        } catch (Exception e) {
            log.error(e.getMessage(), e.getCause());
            fail("Exception thrown");
        }
        assertNotNull(foreignToken);
        //checking if foreign token is valid including client certificate - dummyplatformaam always confirms.
        assertEquals(ValidationStatus.VALID, validationHelper.validate(foreignToken.toString(), "", "", dummyPlatformAAMPEMCertString));
        //changing federation not to contain this platform
        platformsId = new ArrayList<>();
        federationMember = new FederationMember();
        federationMember.setPlatformId("testPlatform");
        platformsId.add(federationMember);
        federationMember = new FederationMember();
        federationMember.setPlatformId("testPlatform2");
        platformsId.add(federationMember);
        federation.setMembers(platformsId);
        federationsRepository.save(federation);

        //checking if foreign token is valid
        assertEquals(ValidationStatus.REVOKED_TOKEN, validationHelper.validate(foreignToken.toString(), "", "", ""));
        //removing federation containing this platform
        federationsRepository.delete(federation);
        assertEquals(ValidationStatus.REVOKED_TOKEN, validationHelper.validate(foreignToken.toString(), "", "", ""));
    }

    @Test
    public void validateForeignTokenOriginCredentialsSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            IOException,
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException,
            UserManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ServiceManagementException {

        userRepository.deleteAll();
        KeyPair keyPair = CryptoHelper.createKeyPair();
        String originHomeTokenJti = String.valueOf(random.nextInt());

        User user = createUser(username, password, recoveryMail, UserRole.USER, AccountStatus.ACTIVE);
        userRepository.save(user);

        //create client certificate
        String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), username, clientId, userKeyPair);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csr);
        String pem = signCertificateRequestService.signCertificateRequest(certRequest);
        Certificate cert = new Certificate(pem);

        user.getClientCertificates().put(clientId, cert);
        userRepository.save(user);

        String foreignTokenString = buildAuthorizationToken(
                username + FIELDS_DELIMITER + clientId + FIELDS_DELIMITER + SecurityConstants.CORE_AAM_INSTANCE_ID + FIELDS_DELIMITER + originHomeTokenJti,
                new HashMap<>(),
                userKeyPair.getPublic().getEncoded(),
                Token.Type.FOREIGN,
                new Date().getTime() + 60000,
                "platform-1",
                keyPair.getPublic(),
                keyPair.getPrivate());

        assertEquals(ValidationStatus.VALID, validationHelper.validateForeignTokenOriginCredentials(foreignTokenString));
    }

    @Test
    public void validateForeignTokenOriginCredentialsFails() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            IOException,
            MalformedJWTException,
            ServiceManagementException,
            WrongCredentialsException,
            UserManagementException,
            ValidationException,
            InvalidArgumentsException,
            NotExistingUserException {

        userRepository.deleteAll();

        KeyPair keyPair = CryptoHelper.createKeyPair();
        String originHomeTokenJti = String.valueOf(random.nextInt());
        String foreignTokenString = buildAuthorizationToken(
                username + FIELDS_DELIMITER + clientId + FIELDS_DELIMITER + SecurityConstants.CORE_AAM_INSTANCE_ID + FIELDS_DELIMITER + originHomeTokenJti,
                new HashMap<>(),
                userKeyPair.getPublic().getEncoded(),
                Token.Type.FOREIGN,
                new Date().getTime() + 60000,
                "coreClient-1",
                keyPair.getPublic(),
                keyPair.getPrivate());

        //no user in database
        assertEquals(ValidationStatus.REVOKED_TOKEN, validationHelper.validateForeignTokenOriginCredentials(foreignTokenString));
        User user = createUser(username, password, recoveryMail, UserRole.USER, AccountStatus.ACTIVE);
        userRepository.save(user);

        //no client in database
        assertEquals(ValidationStatus.REVOKED_TOKEN, validationHelper.validateForeignTokenOriginCredentials(foreignTokenString));
        KeyPair wrongKeyPair = CryptoHelper.createKeyPair();
        //create client certificate
        String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), username, clientId, wrongKeyPair);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csr);
        String pem = signCertificateRequestService.signCertificateRequest(certRequest);
        Certificate cert = new Certificate(pem);

        user.getClientCertificates().put(clientId, cert);
        userRepository.save(user);

        //client public key not matching this in database
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, validationHelper.validateForeignTokenOriginCredentials(foreignTokenString));
    }

    @Test
    public void validateForeignTokenOriginJtiFails() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            IOException,
            MalformedJWTException,
            ValidationException,
            InvalidArgumentsException,
            UserManagementException,
            WrongCredentialsException,
            NotExistingUserException,
            ServiceManagementException {

        userRepository.deleteAll();

        KeyPair keyPair = CryptoHelper.createKeyPair();
        Token homeToken = new Token(buildAuthorizationToken(
                username + FIELDS_DELIMITER + clientId + FIELDS_DELIMITER + SecurityConstants.CORE_AAM_INSTANCE_ID,
                new HashMap<>(),
                userKeyPair.getPublic().getEncoded(),
                Token.Type.HOME,
                new Date().getTime() + 60000,
                "coreClient-1",
                keyPair.getPublic(),
                keyPair.getPrivate()));

        Token foreignToken = new Token(buildAuthorizationToken(
                username + FIELDS_DELIMITER + clientId + FIELDS_DELIMITER + SecurityConstants.CORE_AAM_INSTANCE_ID + FIELDS_DELIMITER + homeToken.getClaims().getId(),
                new HashMap<>(),
                userKeyPair.getPublic().getEncoded(),
                Token.Type.FOREIGN,
                new Date().getTime() + 60000,
                "coreClient-1",
                keyPair.getPublic(),
                keyPair.getPrivate()));

        User user = createUser(username, password, recoveryMail, UserRole.USER, AccountStatus.ACTIVE);
        userRepository.save(user);
        //create client certificate
        String csr = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), username, clientId, userKeyPair);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csr);
        String pem = signCertificateRequestService.signCertificateRequest(certRequest);
        Certificate cert = new Certificate(pem);

        user.getClientCertificates().put(clientId, cert);
        userRepository.save(user);

        revokedTokensRepository.save(homeToken);

        //originHomeToken with JTI that foreign token is identified by is revoked
        assertEquals(ValidationStatus.REVOKED_TOKEN, validationHelper.validateForeignTokenOriginCredentials(foreignToken.getToken()));
    }


    @Test
    public void validateForeignTokenOriginCredentialsPlatformAAMProblems() throws
            IOException,
            ValidationException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            InterruptedException,
            MalformedJWTException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        User platformOwner = savePlatformOwner();
        //inject dummy platform with platform PEM Certificate to the database
        X509Certificate certificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        String dummyPlatformAAMPEMCertString = CryptoHelper.convertX509ToPEM(certificate);
        Platform dummyPlatform = new Platform("platform-1",
                serverAddress + "/test",
                platformInstanceFriendlyName,
                platformOwner,
                new Certificate(dummyPlatformAAMPEMCertString),
                new HashMap<>());
        //put any valid certificate as client cert to pass validation
        dummyPlatform.getComponentCertificates().put(clientId, new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);


        // adding a federation
        List<FederationMember> platformsId = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId("testPlatform");
        platformsId.add(federationMember);
        federationMember = new FederationMember();
        federationMember.setPlatformId("testPlatform2");
        platformsId.add(federationMember);

        Federation federation = new Federation();
        federation.setMembers(platformsId);
        federation.setId("federationId");

        federationsRepository.save(federation);

        Token foreignToken = null;
        try {
            foreignToken = tokenIssuer.getForeignToken(dummyHomeToken);
        } catch (Exception e) {
            log.error(e.getMessage(), e.getCause());
            fail("Exception thrown");
        }
        assertNotNull(foreignToken);
        //checking if foreign token is valid including client certificate - dummyplatformaam always confirms.
        assertEquals(ValidationStatus.VALID, validationHelper.validate(foreignToken.toString(), "", "", dummyPlatformAAMPEMCertString));
        //changing platforms address to make it not available
        dummyPlatform.setPlatformInterworkingInterfaceAddress(serverAddress + "/wrong/url");
        platformRepository.save(dummyPlatform);
        Thread.sleep(validTokenCacheExpirationTime);
        //checking if foreign token is valid
        assertEquals(ValidationStatus.UNKNOWN, validationHelper.validate(foreignToken.toString(), "", "", ""));
        //deleting platform from database
        platformRepository.delete(dummyPlatform);
        //checking if foreign token is valid
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, validationHelper.validate(foreignToken.toString(), "", "", ""));

    }

    @Test
    public void validateForeignTokenRequestFailsConnectionProblems() throws
            IOException,
            ValidationException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            MalformedJWTException,
            ClassNotFoundException,
            AAMException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAMConnectionProblem.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "testaam-connerr";

        saveUser();
        User platformOwner = savePlatformOwner();
        //inject dummy platform with platform PEM Certificate to the database
        X509Certificate certificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        String dummyPlatformAAMPEMCertString = CryptoHelper.convertX509ToPEM(certificate);
        Platform dummyPlatform = new Platform(platformId,
                serverAddress + "/test/conn_err",
                platformInstanceFriendlyName,
                platformOwner,
                new Certificate(dummyPlatformAAMPEMCertString),
                new HashMap<>());
        //put any valid certificate as client cert to pass validation
        dummyPlatform.getComponentCertificates().put(clientId, new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // check if validation will fail due to for example connection problems
        ValidationStatus response = validationHelper.validateRemotelyIssuedToken(dummyHomeToken.getToken(), "", "", "");
        assertEquals(ValidationStatus.ISSUING_AAM_UNREACHABLE, response);
    }


    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateISSMismatch() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000L,
                "bad_issuer", // mismatch token ISS
                properAAMCert.getPublicKey(),
                getPrivateKeyTestFromKeystore("keystores/platform_1.p12", "platform-1-1-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }


    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateIPKMismatch() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        X509Certificate wrongAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-2-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000L,
                "platform-1",
                wrongAAMCert.getPublicKey(), // mismatch token IPK
                getPrivateKeyTestFromKeystore("keystores/platform_1.p12", "platform-1-2-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }

    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateSignatureMismatch() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

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
                getPrivateKeyTestFromKeystore("keystores/platform_1.p12", "platform-1-2-c1") // token signature mismatch
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }

    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateSPKMismatch() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                properAAMCert.getPublicKey().getEncoded(), // mismatch token SPK
                Token.Type.HOME,
                100000L,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyTestFromKeystore("keystores/platform_1.p12", "platform-1-1-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }


    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateSUBMismatch() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "bad_token_sub", // mismatch token SUB
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000L,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyTestFromKeystore("keystores/platform_1.p12", "platform-1-1-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }

    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateChainMismatch() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException, UnrecoverableKeyException {

        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        X509Certificate wrongAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-2-c1");

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

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(wrongAAMCert),
                        "")
        );
    }


    @Test
    public void validateRemoteHomeTokenRequestUsingCertificateMissingChainElement() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException, UnrecoverableKeyException {

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

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        "",
                        "")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        "",
                        "",
                        "")
        );
    }

    @Test
    public void validateRemoteForeignTokenRequestUsingCertificateSUBMismatch() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException, UnrecoverableKeyException {
        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        X509Certificate tokenIssuerAAMCert = getCertificateFromTestKeystore("keystores/platform_2.p12", "platform-2-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId@wrong-platform-id",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.FOREIGN,
                100000L,
                "platform-2",
                tokenIssuerAAMCert.getPublicKey(),
                getPrivateKeyTestFromKeystore("keystores/platform_2.p12", "platform-2-1-c1")
        );

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        CryptoHelper.convertX509ToPEM(tokenIssuerAAMCert))
        );

    }

    @Test
    public void validateRemoteForeignTokenRequestUsingCertificateMissingTokenIssuerCert() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException, UnrecoverableKeyException {
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

        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        CryptoHelper.convertX509ToPEM(userCertificate),
                        CryptoHelper.convertX509ToPEM(properAAMCert),
                        "")
        );
    }


    @Test
    public void rootCAChainValidationSuccess() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            IOException {
        assertTrue(certificationAuthorityHelper.isServiceCertificateChainTrusted(certificationAuthorityHelper.getRootCACert()));
    }

    @Test
    public void validateRemoteTokenInvalidAndRevoked() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            UnrecoverableKeyException,
            ValidationException {


        User platformOwner = savePlatformOwner();
        //inject dummy platform with platform PEM Certificate to the database
        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        // registering the platform to the Core AAM so it will be available for token revocation
        String dummyPlatformAAMPEMCertString = CryptoHelper.convertX509ToPEM(properAAMCert);
        Platform dummyPlatform = new Platform("platform-1",
                serverAddress + "/test/failvalidation",
                platformInstanceFriendlyName,
                platformOwner,
                new Certificate(dummyPlatformAAMPEMCertString),
                new HashMap<>());
        //put any valid certificate as client cert to pass validation
        dummyPlatform.getComponentCertificates().put(clientId, new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

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
        Token homeToken = new Token(testHomeToken);
        assertFalse(revokedTokensRepository.exists(homeToken.getId()));
        // valid remote home token chain (INVALID_TRUST_CHAIN returned by dummyPlatformAAM)
        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        "",
                        "",
                        "")
        );
        // check, if invalid token saved in local repo
        assertTrue(revokedRemoteTokensRepository.exists(homeToken.getClaims().getIssuer() + FIELDS_DELIMITER + homeToken.getId()));
        // check, if token was recognized as revoked during remote validation
        assertEquals(
                ValidationStatus.REVOKED_TOKEN,
                validationHelper.validate(
                        testHomeToken,
                        "",
                        "",
                        "")
        );

    }

    @Test
    public void validateForeignTokenOriginCredentialsInvalidAndRevoked() throws
            IOException,
            ValidationException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            MalformedJWTException {
        // issuing dummy platform token
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        User platformOwner = savePlatformOwner();
        // registering the platform to the Core AAM so it will be available for token revocation
        String dummyPlatformAAMPEMCertString = CryptoHelper.convertX509ToPEM(properAAMCert);
        Platform dummyPlatform = new Platform("platform-1",
                serverAddress + "/test/failvalidation",
                platformInstanceFriendlyName,
                platformOwner,
                new Certificate(dummyPlatformAAMPEMCertString),
                new HashMap<>());
        //put any valid certificate as client cert to pass validation
        dummyPlatform.getComponentCertificates().put(clientId, new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // adding a federation
        List<FederationMember> platformsId = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId("testPlatform");
        platformsId.add(federationMember);
        federationMember = new FederationMember();
        federationMember.setPlatformId("testPlatform2");
        platformsId.add(federationMember);

        Federation federation = new Federation();
        federation.setMembers(platformsId);
        federation.setId("federationId");

        federationsRepository.save(federation);

        Token foreignToken = null;
        try {
            foreignToken = tokenIssuer.getForeignToken(dummyHomeToken);
        } catch (Exception e) {
            log.error(e.getMessage(), e.getCause());
            fail("Exception thrown");
        }
        assertNotNull(foreignToken);
        //checking if foreign token is valid
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, validationHelper.validate(foreignToken.toString(), "", "", ""));
        //checking, if token saved as revoked
        assertTrue(revokedTokensRepository.exists(foreignToken.getId()));
        //checking if foreign token is valid - validation should recognize token as revoked
        assertEquals(ValidationStatus.REVOKED_TOKEN, validationHelper.validate(foreignToken.toString(), "", "", ""));
    }

    @Test(expected = HttpServerErrorException.class)
    public void validateOriginOfForeignTokenFailBadToken() {
        restTemplate.postForEntity(
                serverAddress + SecurityConstants.AAM_VALIDATE_FOREIGN_TOKEN_ORIGIN_CREDENTIALS,
                new Token(), ValidationStatus.class);
        fail("Validation passed with empty token");
    }

    @Test
    public void validateOriginOfForeignTokenFailNotOurToken() throws
            IOException,
            ValidationException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            JWTCreationException,
            AAMException {
        // issuing dummy platform token
        String username = "userId";
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "platform-1";

        //user registration useful
        User platformOwner = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER, AccountStatus.NEW);
        userRepository.save(platformOwner);

        // platform registration useful
        //inject platform PEM Certificate to the database
        X509Certificate platformAAMCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        Platform platform = new Platform(platformId, serverAddress + "/test", "irrelevant", platformOwner, new Certificate(CryptoHelper.convertX509ToPEM(platformAAMCertificate)), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedServices().add(platformId);
        userRepository.save(platformOwner);

        String clientCertificate = CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1"));

        //checking token attributes
        JWTClaims claims = JWTEngine.getClaimsFromToken(dummyHomeToken.getToken());
        assertTrue(claims.getAtt().containsKey("name"));
        assertTrue(claims.getAtt().containsValue("test2"));
        // adding a federation
        List<FederationMember> platformsId = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId(platformId);
        platformsId.add(federationMember);

        Federation federation = new Federation();
        federation.setMembers(platformsId);
        federation.setId("federationId");

        federationsRepository.save(federation);

        // checking issuing of foreign token using the dummy platform token
        String token = aamClient.getForeignToken(dummyHomeToken.getToken(), Optional.of(clientCertificate), Optional.of(CryptoHelper.convertX509ToPEM(platformAAMCertificate)));
        // check if returned status is ok and if there is token in header
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token);
        assertEquals(Token.Type.FOREIGN, Token.Type.valueOf(claimsFromToken.getTtyp()));
        assertTrue(claimsFromToken.getAtt().containsKey("federation_1"));
        assertTrue(claimsFromToken.getAtt().containsValue("federationId"));

        assertEquals(ValidationStatus.WRONG_AAM, restTemplate.postForEntity(
                serverAddress + SecurityConstants.AAM_VALIDATE_FOREIGN_TOKEN_ORIGIN_CREDENTIALS,
                new Token(token), ValidationStatus.class).getBody());
    }
}
