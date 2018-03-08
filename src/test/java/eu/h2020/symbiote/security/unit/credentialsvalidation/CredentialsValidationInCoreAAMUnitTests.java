package eu.h2020.symbiote.security.unit.credentialsvalidation;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.RevokedRemoteTokensRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAMConnectionProblem;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import javax.security.auth.x500.X500Principal;
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
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    @Value("${rabbit.queue.ownedservices.request}")
    protected String ownedServicesRequestQueue;
    @Autowired
    protected UserRepository userRepository;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    String coreInterfaceAddress;
    @Autowired
    private ValidationHelper validationHelper;
    @Autowired
    private TokenIssuer tokenIssuer;
    @Autowired
    protected RevokedRemoteTokensRepository revokedRemoteTokensRepository;
    @Autowired
    private DummyPlatformAAM dummyPlatformAAM;
    @Autowired
    private DummyCoreAAM dummyCoreAAM;
    @Autowired
    private DummyPlatformAAMConnectionProblem dummyPlatformAAMConnectionProblem;

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
                        new HashMap<>(),
                        new HashMap<>()),
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
    public void validateIssuerDiffersDeploymentIdAndRelayValidation() throws
            IOException,
            ValidationException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            ClassNotFoundException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);

        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

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

        // check if platform token is is valid
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

    // test for relay
    @Test
    public void validateForeignTokenIssuerNotInAvailableAAMs() throws
            IOException,
            ValidationException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            MalformedJWTException,
            ClassNotFoundException {
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
            MalformedJWTException,
            ClassNotFoundException {
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

        platformsId = new ArrayList<>();
        federationMember = new FederationMember();
        federationMember.setPlatformId(dummyPlatform.getPlatformInstanceId());
        platformsId.add(federationMember);
        federationMember = new FederationMember();
        federationMember.setPlatformId("testPlatform");
        platformsId.add(federationMember);

        federation = new Federation();
        federation.setMembers(platformsId);
        federation.setId("federationId2");

        federationsRepository.save(federation);

        platformsId = new ArrayList<>();
        federationMember = new FederationMember();
        federationMember.setPlatformId(dummyPlatform.getPlatformInstanceId());
        platformsId.add(federationMember);
        federationMember = new FederationMember();
        federationMember.setPlatformId("testPlatform");
        platformsId.add(federationMember);
        federationMember = new FederationMember();
        federationMember.setPlatformId("testPlatform2");
        platformsId.add(federationMember);

        federation = new Federation();
        federation.setMembers(platformsId);
        federation.setId("federationId3");

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

        assertEquals(2, federationsRepository.findOne("federationId3").getMembers().size());

        //checking if foreign token is valid
        assertEquals(ValidationStatus.REVOKED_TOKEN, validationHelper.validate(foreignToken.toString(), "", "", ""));
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
            OperatorCreationException,
            MalformedJWTException {

        userRepository.deleteAll();
        KeyPair keyPair = CryptoHelper.createKeyPair();
        String originHomeTokenJti = String.valueOf(random.nextInt());
        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password),
                        "nullMail", UserRole.USER, new HashMap<>(), new HashMap<>()), OperationType.CREATE);


        User user = createUser(userManagementRequest.getUserDetails().getCredentials().getUsername(), userManagementRequest.getUserDetails().getCredentials().getPassword(), userManagementRequest.getUserDetails().getRecoveryMail(), userManagementRequest.getUserDetails().getRole());

        //create client certificate
        String cn = "CN=" + username + "@" + clientId + "@" + SecurityConstants.CORE_AAM_INSTANCE_ID;
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), userKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(userKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSRinPEMFormat());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
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
            OperatorCreationException,
            MalformedJWTException {

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

        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password),
                        "nullMail", UserRole.USER, new HashMap<>(), new HashMap<>()), OperationType.CREATE);

        User user = createUser(userManagementRequest.getUserDetails().getCredentials().getUsername(), userManagementRequest.getUserDetails().getCredentials().getPassword(), userManagementRequest.getUserDetails().getRecoveryMail(), userManagementRequest.getUserDetails().getRole());
        userRepository.save(user);

        //no client in database
        assertEquals(ValidationStatus.REVOKED_TOKEN, validationHelper.validateForeignTokenOriginCredentials(foreignTokenString));
        KeyPair wrongKeyPair = CryptoHelper.createKeyPair();
        //create client certificate
        String cn = "CN=" + username + "@" + clientId + "@" + SecurityConstants.CORE_AAM_INSTANCE_ID;
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), wrongKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(wrongKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSRinPEMFormat());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
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
            OperatorCreationException,
            MalformedJWTException,
            ValidationException {

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


        UserManagementRequest userManagementRequest = new UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new Credentials(username, password),
                new UserDetails(new Credentials(username, password),
                        "nullMail", UserRole.USER, new HashMap<>(), new HashMap<>()), OperationType.CREATE);


        User user = createUser(userManagementRequest.getUserDetails().getCredentials().getUsername(), userManagementRequest.getUserDetails().getCredentials().getPassword(), userManagementRequest.getUserDetails().getRecoveryMail(), userManagementRequest.getUserDetails().getRole());

        //create client certificate
        String cn = "CN=" + username + "@" + clientId + "@" + SecurityConstants.CORE_AAM_INSTANCE_ID;
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), userKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(userKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSRinPEMFormat());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
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
            MalformedJWTException,
            ClassNotFoundException {
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
    public void validateForeignTokenRequestFails() throws
            IOException,
            ValidationException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            MalformedJWTException,
            ClassNotFoundException {
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
        assertEquals(ValidationStatus.WRONG_AAM, response);
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
                100000l,
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
                100000l,
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
                100000l,
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
                100000l,
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
                100000l,
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
                100000l,
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
                100000l,
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
                100000l,
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
                100000l,
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
            KeyStoreException,
            IOException {
        assertTrue(validationHelper.certificationAuthorityHelper.isServiceCertificateChainTrusted(certificationAuthorityHelper.getRootCACert()));
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
                100000l,
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
            MalformedJWTException,
            ClassNotFoundException {
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
}
