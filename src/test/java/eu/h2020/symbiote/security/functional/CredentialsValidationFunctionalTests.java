package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.ValidationRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class CredentialsValidationFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(CredentialsValidationFunctionalTests.class);

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interface: PAAM - 2, CAAM - 1
     * CommunicationType AMQP
     *
     */
    @Test
    public void validationOverAMQPRequestReplyValid() throws
            IOException,
            TimeoutException,
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            InvalidKeyException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String token = aamClient.getHomeToken(loginRequest);
        assertNotNull(token);

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                validateRequestQueue,
                10000);
        byte[] amqpResponse = client.primitiveCall(mapper.writeValueAsString(new ValidationRequest(token, "", "", "")).getBytes());
        ValidationStatus validationStatus = mapper.readValue(amqpResponse,
                ValidationStatus.class);

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
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            InvalidKeyException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);


        String homeToken = aamClient.getHomeToken(loginRequest);

        ValidationStatus status = aamClient.validateCredentials(homeToken, Optional.empty(), Optional.empty(), Optional.empty());
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
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            InvalidKeyException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException {
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
            InterruptedException,
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            InvalidKeyException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException {
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
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            InvalidKeyException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException, ValidationException {

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
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            InvalidKeyException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException, ValidationException {

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

}
