package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.CoreAttributes;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.interfaces.payloads.*;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.codehaus.jettison.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class TokensIssuingFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(TokensIssuingFunctionalTests.class);
    private final String coreAppUsername = "testCoreAppUsername";
    private final String coreAppPassword = "testCoreAppPassword";
    private final String recoveryMail = "null@dev.null";
    private final String federatedOAuthId = "federatedOAuthId";
    private final String platformId = "testPlatformId";
    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
    private final String platformOwnerUsername = "testPlatformOwnerUsername";
    private final String platformOwnerPassword = "testPlatormOwnerPassword";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    private KeyPair platformOwnerKeyPair;
    private UserManagementRequest appUserManagementRequest;
    private RpcClient appRegistrationClient;
    private UserDetails appUserDetails;
    private RpcClient platformRegistrationOverAMQPClient;
    private Credentials platformOwnerUserCredentials;
    private PlatformManagementRequest platformRegistrationOverAMQPRequest;
    @Autowired
    private PlatformRepository platformRepository;

    @Autowired
    private TokenIssuer tokenIssuer;

    @Bean
    DummyPlatformAAM getDummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // db cleanup
        platformRepository.deleteAll();

        // user registration useful
        appRegistrationClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                userRegistrationRequestQueue, 5000);
        appUserDetails = new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.USER);
        appUserManagementRequest = new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), appUserDetails);

        //user registration useful
        User user = new User();
        user.setUsername(platformOwnerUsername);
        user.setPasswordEncrypted(passwordEncoder.encode(platformOwnerPassword));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(user);

        // platform registration useful
        platformRegistrationOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformRegistrationRequestQueue, 5000);
        platformOwnerUserCredentials = new Credentials(user.getUsername(), user.getPasswordEncrypted());
        platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, platformInterworkingInterfaceAddress,
                platformInstanceFriendlyName,
                preferredPlatformId);
        platformOwnerKeyPair = CryptoHelper.createKeyPair();

    }

    /**
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1 and CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void getHomeTokenForUserOverAMQPSuccessAndIssuesCoreTokenType() throws IOException, TimeoutException, MalformedJWTException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException {
        addTestUserWithClientCertificateToRepository();
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        byte[] response = client.primitiveCall(mapper.writeValueAsString(CryptoHelper.signedObjectToString(signObject))
                .getBytes());
        Token token = mapper.readValue(response, Token.class);

        log.info("Test Client received this Token: " + token.toString());

        // check if token received
        assertNotNull(token);
        // check if issuing authority is core
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));
    }


    /**
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void getHomeTokenForUserOverAMQPWrongCredentialsFailure() throws IOException, TimeoutException {

        // test combinations of wrong credentials
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        SignedObject signObject = CryptoHelper.objectToSignedObject(wrongusername + "@" + clientId, userKeyPair.getPrivate());

        byte[] response = client.primitiveCall(mapper.writeValueAsString(CryptoHelper.signedObjectToString(signObject))
                .getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        signObject = CryptoHelper.objectToSignedObject(username + "@" + wrongClientId, userKeyPair.getPrivate());
        byte[] response2 = client.primitiveCall(mapper.writeValueAsString(CryptoHelper.signedObjectToString(signObject))
                .getBytes());
        ErrorResponseContainer noToken2 = mapper.readValue(response2, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken2.getErrorMessage());
        signObject = CryptoHelper.objectToSignedObject(wrongusername + "@" + wrongClientId, userKeyPair.getPrivate());

        byte[] response3 = client.primitiveCall(mapper.writeValueAsString(CryptoHelper.signedObjectToString(signObject)).getBytes());
        ErrorResponseContainer noToken3 = mapper.readValue(response3, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken3.getErrorMessage());

        String expectedErrorMessage = new WrongCredentialsException().getErrorMessage();

        assertEquals(expectedErrorMessage, noToken.getErrorMessage());
        assertEquals(expectedErrorMessage, noToken2.getErrorMessage());
        assertEquals(expectedErrorMessage, noToken3.getErrorMessage());
    }

    /**
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void getHomeTokenForUserOverAMQPMissingArgumentsFailure() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        SignedObject signObject = CryptoHelper.objectToSignedObject("@", userKeyPair.getPrivate());
        byte[] response = client.primitiveCall(mapper.writeValueAsString(CryptoHelper.signedObjectToString(signObject)).getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        assertEquals(new MissingArgumentsException().getErrorMessage(), noToken.getErrorMessage());
    }

    /**
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void getHomeTokenForUserOverAMQPWrongSignFailure() throws IOException, TimeoutException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        KeyPair keyPair = CryptoHelper.createKeyPair();
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, keyPair.getPrivate());
        byte[] response = client.primitiveCall(mapper.writeValueAsString(CryptoHelper.signedObjectToString(signObject)).getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());
        assertEquals(new WrongCredentialsException().getErrorMessage(), noToken.getErrorMessage());
    }

    @Test
    public void getHomeTokenForUserOverRESTWrongSignFailure() throws IOException, TimeoutException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        ResponseEntity<ErrorResponseContainer> token = null;
        KeyPair keyPair = CryptoHelper.createKeyPair();
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, keyPair.getPrivate());
        try {
            token = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN, CryptoHelper.signedObjectToString(signObject),
                    ErrorResponseContainer.class);
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.UNAUTHORIZED.value(), e.getRawStatusCode());
        }
        assertNull(token);
    }

    @Test
    public void getHomeTokenForUserOverRESTWrongUsernameFailure() throws IOException {

        SignedObject signObject = CryptoHelper.objectToSignedObject(wrongusername + "@" + clientId, userKeyPair.getPrivate());
        try {
            restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN, CryptoHelper.signedObjectToString(signObject), ErrorResponseContainer.class);
            fail("No error thrown");
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.UNAUTHORIZED.value(), e.getRawStatusCode());
        }
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void getHomeTokenForUserOverRESTWrongClientIdFailure() throws IOException {
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + wrongClientId, userKeyPair.getPrivate());
        try {
            restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN, CryptoHelper.signedObjectToString(signObject), ErrorResponseContainer.class);
            fail("No error thrown");
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.UNAUTHORIZED.value(), e.getRawStatusCode());
        }
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void getHomeTokenForUserOverRESTSuccessAndIssuesCoreTokenWithoutPOAttributes() throws IOException, MalformedJWTException, CertificateException, OperatorCreationException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidKeyException {
        addTestUserWithClientCertificateToRepository();

        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        // As the AAM is now configured as core we confirm that relevant token type was issued.
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        // verify that this JWT contains attributes relevant for user role
        Map<String, String> attributes = claimsFromToken.getAtt();
        assertEquals(UserRole.USER.toString(), attributes.get(CoreAttributes.ROLE.toString()));

        // verify that the token contains the user public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (username).getClientCertificates().entrySet().iterator().next().getValue().getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.getDecoder().decode(claimsFromToken.getSpk());

        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);
    }

    /**
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */
    @Test
    public void getForeignTokenRequestOverRESTFailsForHomeTokenUsedAsRequest() throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException {
        addTestUserWithClientCertificateToRepository();
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(SecurityConstants.TOKEN_HEADER_NAME, loginHeaders.getFirst(SecurityConstants.TOKEN_HEADER_NAME));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        try {
            restTemplate.postForEntity(serverAddress + SecurityConstants
                            .AAM_GET_FOREIGN_TOKEN, request,
                    String.class);
            assert false;
        } catch (RestClientException e) {
            // TODO think of a better way to assert that BAD_REQUEST
            log.error(e);
            assertNotNull(e);
        }

    }

    @Test
    public void getGuestTokenOverRESTSuccess() throws MalformedJWTException {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_GUEST_TOKEN,
                null,
                String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        assertEquals(Token.Type.GUEST, Token.Type.valueOf(claimsFromToken.getTtyp()));
        assertTrue(claimsFromToken.getAtt().isEmpty());
    }


    @Test
    public void getForeignTokenUsingPlatformTokenOverRESTSuccess() throws IOException, ValidationException, TimeoutException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, MalformedJWTException {
        // issuing dummy platform token
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "platform-1";
        // registering the platform to the Core AAM so it will be available for token revocation
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(platformId);
        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress(serverAddress + "/test");
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        //inject platform PEM Certificate to the database
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/platform_1.p12"), "1234567".toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate("platform-1-1-c1");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        String dummyPlatformAAMPEMCertString = signedCertificatePEMDataStringWriter.toString();
        Platform dummyPlatform = platformRepository.findOne(platformId);
        dummyPlatform.setPlatformAAMCertificate(new eu.h2020.symbiote.security.commons.Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // preparing request
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(SecurityConstants.TOKEN_HEADER_NAME, dummyHomeToken.getToken());

        HttpEntity<String> entity = new HttpEntity<>(null, httpHeaders);

        // adding a dummy foreign rule
        tokenIssuer.foreignMappingRules.put("DummyRule", "dummyRule");

        // checking issuing of foreign token using the dummy platform token
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants
                .AAM_GET_FOREIGN_TOKEN, entity, String.class);
        HttpHeaders rspHeaders = response.getHeaders();

        // check if returned status is ok and if there is token in header
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(rspHeaders.getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(rspHeaders.getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        assertEquals(Token.Type.FOREIGN, Token.Type.valueOf(claimsFromToken.getTtyp()));
    }


    /**
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */
    @Test
    public void getForeignTokenFromCoreUsingPlatformTokenOverRESTFailsForUndefinedForeignMapping() throws IOException, ValidationException, TimeoutException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
        // issuing dummy platform token
        SignedObject signObject = CryptoHelper.objectToSignedObject(username + "@" + clientId, userKeyPair.getPrivate());
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "platform-1";
        // registering the platform to the Core AAM so it will be available for token revocation
        platformRegistrationOverAMQPRequest.setPlatformInstanceId(platformId);
        platformRegistrationOverAMQPRequest.setPlatformInterworkingInterfaceAddress(serverAddress + "/test");
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        //inject platform PEM Certificate to the database
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/platform_1.p12"), "1234567".toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate("platform-1-1-c1");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        String dummyPlatformAAMPEMCertString = signedCertificatePEMDataStringWriter.toString();
        Platform dummyPlatform = platformRepository.findOne(platformId);
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);

        // preparing request
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(SecurityConstants.TOKEN_HEADER_NAME, dummyHomeToken.getToken());

        HttpEntity<String> entity = new HttpEntity<>(null, httpHeaders);

        // making sure the foreignMappingRules are empty
        tokenIssuer.foreignMappingRules.clear();

        // checking issuing of foreign token using the dummy platform token
        try {
            ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants
                    .AAM_GET_FOREIGN_TOKEN, entity, String.class);
            assert false;
        } catch (HttpServerErrorException e) {
            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), e.getRawStatusCode());
        }
    }

    /**
     * Features: CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void getHomeTokenForPlatformOwnerOverRESTSuccessAndIssuesRelevantTokenTypeWithPOAttributes() throws IOException, TimeoutException, MalformedJWTException, CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, OperatorCreationException, UnrecoverableKeyException, InvalidKeyException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        User user = userRepository.findOne(platformOwnerUsername);
        //platform owner adding
        String cn = "CN=" + platformOwnerUsername + "@" + platformId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), platformOwnerKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(platformOwnerKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, csr);
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSR());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        Certificate cert = new Certificate(pem);
        user.getClientCertificates().put(platformId, cert);
        userRepository.save(user);

        SignedObject signObject = CryptoHelper.objectToSignedObject(platformOwnerUsername + "@" + platformId, platformOwnerKeyPair.getPrivate());
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        //verify that JWT was issued for user
        assertNotNull(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));

        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));

        //verify that JWT is of type Core as was released by a CoreAAM
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        // verify that the token contains the platform owner public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (platformOwnerUsername).getClientCertificates().get(platformId).getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.getDecoder().decode(claimsFromToken.getSpk());
        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);

        // verify that this JWT contains attributes relevant for platform owner
        Map<String, String> attributes = claimsFromToken.getAtt();
        // PO role
        assertEquals(UserRole.PLATFORM_OWNER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        // owned platform identifier
        assertEquals(preferredPlatformId, attributes.get(CoreAttributes.OWNED_PLATFORM.toString()));
    }

    /**
     * Features: CAAM - Providing platform details for Administration upon giving a correct Core Token
     * Interfaces: CAAM ;
     * CommunicationType AMQP
     */
    @Test
    public void getHomeTokenForPlatformOwnerOverRESTAndReceivesInAdministrationDetailsOfHisOwnedPlatform() throws IOException,
            TimeoutException, MalformedJWTException, JSONException, CertificateException, ValidationException,
            InterruptedException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, OperatorCreationException, UnrecoverableKeyException, InvalidKeyException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        User user = userRepository.findOne(platformOwnerUsername);
        //platform owner adding certificate
        String cn = "CN=" + platformOwnerUsername + "@" + preferredPlatformId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), platformOwnerKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(platformOwnerKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, preferredPlatformId, csr);
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSR());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        Certificate cert = new Certificate(pem);
        user.getClientCertificates().clear();
        user.getClientCertificates().put(preferredPlatformId, cert);
        userRepository.save(user);

        // getHomeToken the platform owner
        SignedObject signedObject = CryptoHelper.objectToSignedObject(platformOwnerUsername + "@" + preferredPlatformId, platformOwnerKeyPair.getPrivate());
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signedObject), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        //verify that JWT was issued for user
        assertNotNull(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME)).getBytes());
        OwnedPlatformDetails ownedPlatformDetails = mapper.readValue(ownedPlatformRawResponse, OwnedPlatformDetails.class);

        Platform ownedPlatformInDB = platformRepository.findOne(preferredPlatformId);

        // verify the contents of the response
        assertEquals(ownedPlatformInDB.getPlatformInstanceFriendlyName(), ownedPlatformDetails
                .getPlatformInstanceFriendlyName());
        assertEquals(ownedPlatformInDB.getPlatformInstanceId(), ownedPlatformDetails.getPlatformInstanceId());
        assertEquals(ownedPlatformInDB.getPlatformInterworkingInterfaceAddress(), ownedPlatformDetails
                .getPlatformInterworkingInterfaceAddress());
    }


    /**
     * Features: CAAM - Providing platform details for Administration upon giving a correct Core Token
     * Interfaces: CAAM ;
     * CommunicationType AMQP
     */
    @Test
    public void getHomeTokenForPlatformOwnerOverRESTAndUsesExpiredTokenToReceivesInAdministrationDetailsOfHisOwnedPlatform()
            throws IOException,
            TimeoutException, MalformedJWTException, JSONException, CertificateException, ValidationException,
            InterruptedException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, OperatorCreationException, UnrecoverableKeyException, InvalidKeyException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());
        User user = userRepository.findOne(platformOwnerUsername);
        String cn = "CN=" + platformOwnerUsername + "@" + platformId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), platformOwnerKeyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(platformOwnerKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, platformId, csr);
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSR());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        Certificate cert = new Certificate(pem);
        user.getClientCertificates().put(platformId, cert);
        userRepository.save(user);

        // getHomeToken the platform owner
        SignedObject signedObject = CryptoHelper.objectToSignedObject(platformOwnerUsername + "@" + platformId, platformOwnerKeyPair.getPrivate());
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signedObject), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        //verify that JWT was issued for user
        assertNotNull(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));

        // waiting for the token to expire
        Thread.sleep(tokenValidityPeriod + 1000);

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME)).getBytes());

        try {
            mapper.readValue(ownedPlatformRawResponse, OwnedPlatformDetails.class);
            assert false;
        } catch (Exception e) {
            ErrorResponseContainer error = mapper.readValue(ownedPlatformRawResponse, ErrorResponseContainer.class);
            assertEquals(HttpStatus.UNAUTHORIZED.value(), error.getErrorCode());
        }
    }

    /**
     * Features: CAAM - Providing platform details for Administration upon giving a correct Core Token
     * Interfaces: CAAM ;
     * CommunicationType AMQP
     */
    @Test
    public void getHomeTokenForPlatformOwnerOverRESTAndIsDeclinedOwnedPlatformDetailsRequestNoPlatform() throws IOException,
            TimeoutException, MalformedJWTException, JSONException, CertificateException, ValidationException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException, OperatorCreationException, UnrecoverableKeyException, InvalidKeyException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        // issue app registration over AMQP
        appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                UserManagementRequest(new
                Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail, UserRole.USER))).getBytes());

        //put certificate into database
        User user = userRepository.findOne(coreAppUsername);
        KeyPair keyPair = CryptoHelper.createKeyPair();
        String cn = "CN=" + coreAppUsername + "@" + platformId + "@" + certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName().split("CN=")[1];
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(cn), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(coreAppUsername, coreAppPassword, platformId, csr);
        byte[] bytes = Base64.getDecoder().decode(certRequest.getClientCSR());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        X509Certificate certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req);
        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        Certificate cert = new Certificate(pem);
        user.getClientCertificates().put(platformId, cert);
        userRepository.save(user);

        // getHomeToken an ordinary user to get token
        SignedObject signObject = CryptoHelper.objectToSignedObject(coreAppUsername + "@" + platformId, keyPair.getPrivate());
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN,
                CryptoHelper.signedObjectToString(signObject), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        //verify that JWT was issued for user
        assertNotNull(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));

        // issue owned platform details request with the given token
        RpcClient rpcClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                ownedPlatformDetailsRequestQueue, 5000);
        byte[] ownedPlatformRawResponse = rpcClient.primitiveCall(mapper.writeValueAsString
                (headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME)).getBytes());

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(ownedPlatformRawResponse, ErrorResponseContainer.class);
        assertEquals(HttpStatus.UNAUTHORIZED.value(), errorResponse.getErrorCode());
    }
}
