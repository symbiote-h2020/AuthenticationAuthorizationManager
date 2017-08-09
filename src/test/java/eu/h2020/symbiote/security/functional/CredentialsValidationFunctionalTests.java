package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.ValidationRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void validationOverAMQPRequestReplyValid() throws IOException, TimeoutException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException, JWTCreationException, MalformedJWTException, WrongCredentialsException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String token = null;
        token = restaamClient.getHomeToken(loginRequest);
        assertNotNull(token);

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                validateRequestQueue,
                10000);
        byte[] amqpResponse = client.primitiveCall(mapper.writeValueAsString(new ValidationRequest(token, "")).getBytes());
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
    public void validationOverRESTValid() throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException, JWTCreationException, MalformedJWTException, WrongCredentialsException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = restaamClient.getHomeToken(loginRequest);
        ValidationStatus status = restaamClient.validate(homeToken, "null");
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
    public void validationOverRESTExpired() throws IOException, InterruptedException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException,
            InvalidKeyException, JWTCreationException, MalformedJWTException, WrongCredentialsException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        String homeToken = restaamClient.getHomeToken(loginRequest);
        //Introduce latency so that JWT expires
        Thread.sleep(tokenValidityPeriod + 10);

        ValidationStatus status = restaamClient.validate(homeToken, "null");

        // TODO cover other situations (bad key, on purpose revocation)
        assertEquals(ValidationStatus.EXPIRED_TOKEN, status);
    }


}
