package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.AbstractAAMAMQPTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import eu.h2020.symbiote.security.communication.payloads.ValidationRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class CredentialsValidationFunctionalTests extends
        AbstractAAMAMQPTestSuite {

    private static Log log = LogFactory.getLog(CredentialsValidationFunctionalTests.class);
    @Autowired
    RabbitTemplate rabbitTemplate;
    private RestTemplate restTemplate = new RestTemplate();
    @Autowired
    private DummyPlatformAAM dummyPlatformAAM;

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interface: PAAM - 2, CAAM - 1
     * CommunicationType AMQP
     */
    @Test
    public void validationOverAMQPRequestReplyValid() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String token = aamClient.getHomeToken(loginRequest);
        assertNotNull(token);
        byte[] response = rabbitTemplate.sendAndReceive(validateRequestQueue, new Message(mapper.writeValueAsBytes(new ValidationRequest(token, "", "", "")), new MessageProperties())).getBody();
        ValidationStatus validationStatus = mapper.readValue(response, ValidationStatus.class);
        log.info("Test Client received this ValidationStatus: " + validationStatus);

        assertEquals(ValidationStatus.VALID, validationStatus);
    }

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
    @Test
    public void validationOverRESTValid() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);


        String homeToken = aamClient.getHomeToken(loginRequest);

        ValidationStatus status = aamClient.validateCredentials(
                homeToken,
                Optional.of(userRepository.findOne(username).getClientCertificates().get(clientId).getCertificateString()),
                Optional.empty(),
                Optional.empty());
        assertEquals(ValidationStatus.VALID, status);
    }

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
    @Test
    public void validationOverRESTExpired() throws
            IOException,
            InterruptedException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        String homeToken = aamClient.getHomeToken(loginRequest);
        //Introduce latency so that JWT expires
        Thread.sleep(tokenValidityPeriod + 10);

        ValidationStatus status = aamClient.validateCredentials(homeToken, Optional.empty(), Optional.empty(), Optional.empty());
        assertEquals(ValidationStatus.EXPIRED_TOKEN, status);
    }

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking wrong generated tokens)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
    @Test
    public void validationOverRESTWrongToken() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            AAMException {
        addTestUserWithClientCertificateToRepository();
        String homeToken = "WrongTokenString";
        ValidationStatus status = aamClient.validateCredentials(homeToken, Optional.empty(), Optional.empty(), Optional.empty());
        assertEquals(ValidationStatus.UNKNOWN, status);
    }

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking already revoked tokens)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
    @Test
    public void validationOverRESTRevokedToken() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            ValidationException,
            AAMException {

        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);


        String homeToken = aamClient.getHomeToken(loginRequest);

        revokedTokensRepository.save(new Token(homeToken));
        assertTrue(revokedTokensRepository.exists(new Token(homeToken).getId()));

        ValidationStatus status = aamClient.validateCredentials(homeToken, Optional.empty(), Optional.empty(), Optional.empty());
        assertEquals(ValidationStatus.REVOKED_TOKEN, status);
    }

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking tokens with revoked keys)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */

    @Test
    public void validationOverRESTRevokedKey() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException {

        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);


        String homeToken = aamClient.getHomeToken(loginRequest);

        SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(username);
        Set<String> keySet = (subjectsRevokedKeys == null) ? new HashSet<>() : subjectsRevokedKeys
                .getRevokedKeysSet();
        keySet.add(Base64.getEncoder().encodeToString(
                userKeyPair.getPublic().getEncoded()));
        // adding key to revoked repository
        revokedKeysRepository.save(new SubjectsRevokedKeys(username, keySet));

        assertNotNull(revokedKeysRepository.findOne(username));

        ValidationStatus status = aamClient.validateCredentials(homeToken, Optional.empty(), Optional.empty(), Optional.empty());
        assertEquals(ValidationStatus.REVOKED_SPK, status);
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
            AAMException,
            ClassNotFoundException {
        // issuing dummy platform token
        String username = "userId";
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "platform-1";

        //user registration useful
        User platformOwner = createUser(platformOwnerUsername, platformOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(platformOwner);

        // platform registration useful
        Credentials platformOwnerUserCredentials = new Credentials(platformOwner.getUsername(), platformOwner.getPasswordEncrypted());
        PlatformManagementRequest platformRegistrationOverAMQPRequest = new PlatformManagementRequest(new Credentials(AAMOwnerUsername,
                AAMOwnerPassword), platformOwnerUserCredentials, serverAddress + "/test",
                "irrelevant",
                platformId, OperationType.CREATE);

        // registering the platform to the Core AAM so it will be available for token revocation
        byte[] response = rabbitTemplate.sendAndReceive(platformManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (platformRegistrationOverAMQPRequest), new MessageProperties())).getBody();
        PlatformManagementResponse platformManagementResponse = mapper.readValue(response, PlatformManagementResponse.class);
        assertEquals(ManagementStatus.OK, platformManagementResponse.getRegistrationStatus());
        //inject platform PEM Certificate to the database
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/platform_1.p12"), "1234567".toCharArray());

        X509Certificate platformAAMCertificate = (X509Certificate) ks.getCertificate("platform-1-1-c1");

        Platform dummyPlatform = platformRepository.findOne(platformId);

        dummyPlatform.setPlatformAAMCertificate(new eu.h2020.symbiote.security.commons.Certificate(CryptoHelper.convertX509ToPEM(platformAAMCertificate)));
        platformRepository.save(dummyPlatform);

        String clientCertificate = CryptoHelper.convertX509ToPEM((X509Certificate) ks.getCertificate("userid@clientid@platform-1"));

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
