package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMAMQPTestSuite;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.ValidationRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@TestPropertySource("/core.properties")
public class CredentialsValidationFunctionalTests extends
        AbstractAAMAMQPTestSuite {

    @Autowired
    RabbitTemplate rabbitTemplate;

    @Test
    public void validationOverAMQPSuccess() throws
            IOException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException, BlockedUserException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String token = aamClient.getHomeToken(loginRequest);
        assertNotNull(token);
        byte[] response = rabbitTemplate.sendAndReceive(validateRequestQueue, new Message(mapper.writeValueAsBytes(new ValidationRequest(token, "", "", "")), new MessageProperties())).getBody();
        ValidationStatus validationStatus = mapper.readValue(response, ValidationStatus.class);
        assertEquals(ValidationStatus.VALID, validationStatus);
    }

    @Test
    public void sendMessageOverAMQPFailWrongMessage() throws
            IOException {
        String wrongmessage = "{wrong message json}";
        // send incorrect message over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(validateRequestQueue, new Message(mapper.writeValueAsBytes
                (wrongmessage), new MessageProperties())).getBody();
        ErrorResponseContainer sspRegistrationOverAMQPResponse = mapper.readValue(response,
                ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), sspRegistrationOverAMQPResponse.getErrorCode());
    }
    @Test
    public void validationOverRESTSuccess() throws
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException, BlockedUserException {
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

    @Test
    public void validationOverRESTFailExpiredToken() throws
            InterruptedException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException, BlockedUserException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        String homeToken = aamClient.getHomeToken(loginRequest);
        //Introduce latency so that JWT expires
        Thread.sleep(tokenValidityPeriod + 10);

        ValidationStatus status = aamClient.validateCredentials(homeToken, Optional.empty(), Optional.empty(), Optional.empty());
        assertEquals(ValidationStatus.EXPIRED_TOKEN, status);
    }
}
