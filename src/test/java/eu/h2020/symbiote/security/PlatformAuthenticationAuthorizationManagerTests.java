package eu.h2020.symbiote.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.aam.MalformedJWTException;
import eu.h2020.symbiote.security.exceptions.aam.MissingArgumentsException;
import eu.h2020.symbiote.security.exceptions.aam.WrongCredentialsException;
import eu.h2020.symbiote.security.payloads.*;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.HttpClientErrorException;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for Platform side AAM deployment scenarios.
 */
@TestPropertySource("/platform.properties")
public class PlatformAuthenticationAuthorizationManagerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(PlatformAuthenticationAuthorizationManagerTests.class);


    /**
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationLoginOverAMQPSuccessAndIssuesPlatformTokenType() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(username, password))
                .getBytes());
        Token token = mapper.readValue(response, Token.class);

        log.info("Test Client received this Token: " + token.toJson());

        assertNotNull(token.getToken());
        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
            assertEquals(IssuingAuthorityType.PLATFORM, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

            // verify that the token contains the application public key
            byte[] applicationPublicKeyInRepository = userRepository.findOne
                    (username).getCertificate().getX509().getPublicKey().getEncoded();
            byte[] publicKeyFromToken = Base64.decodeBase64(claimsFromToken.getSpk());
            assertArrayEquals(applicationPublicKeyInRepository, publicKeyFromToken);
        } catch (MalformedJWTException | CertificateException e) {
            log.error(e);
        }
    }


    /**
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationLoginOverAMQPWrongCredentialsFailure() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);

        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(wrongusername, password))
                .getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        byte[] response2 = client.primitiveCall(mapper.writeValueAsString(new Credentials(username, wrongpassword))
                .getBytes());
        ErrorResponseContainer noToken2 = mapper.readValue(response2, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken2.getErrorMessage());

        byte[] response3 = client.primitiveCall(mapper.writeValueAsString(new Credentials(wrongusername,
                wrongpassword)).getBytes());
        ErrorResponseContainer noToken3 = mapper.readValue(response3, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken3.getErrorMessage());

        String expectedErrorMessage = new WrongCredentialsException().getErrorMessage();

        assertEquals(expectedErrorMessage, noToken.getErrorMessage());
        assertEquals(expectedErrorMessage, noToken2.getErrorMessage());
        assertEquals(expectedErrorMessage, noToken3.getErrorMessage());
    }

    /**
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationLoginOverAMQPMissingArgumentsFailure() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(/* no username and/or
        password */)).getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        assertEquals(new MissingArgumentsException().getErrorMessage(), noToken.getErrorMessage());
    }


    /**
     * Feature: PAAM - 2 (Application Registration)
     * Interface: PAAM - 3a
     * CommunicationType REST
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationRegistrationOverRESTSuccess() throws JsonProcessingException {
        String testAppUsername = "NewApplication";
        UserRegistrationRequest request = new UserRegistrationRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new UserDetails(new Credentials(testAppUsername, "NewPassword"), "", "", UserRole.APPLICATION));
        try {
            // verify that app is not in the repository
            User registeredUser = userRepository.findOne(testAppUsername);
            assertNull(registeredUser);

            ResponseEntity<UserRegistrationResponse> response = restTemplate.postForEntity(serverAddress +
                    registrationUri, request, UserRegistrationResponse.class);
            assertEquals(HttpStatus.OK, response.getStatusCode());
            // verify that app really is in repository
            registeredUser = userRepository.findOne(testAppUsername);
            assertNotNull(registeredUser);
            assertEquals(UserRole.APPLICATION, registeredUser.getRole());

            // verify that the server returns certificate & privateKey
            assertNotNull(response.getBody().getPemCertificate());
            assertNotNull(response.getBody().getPemPrivateKey());
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.BAD_REQUEST.value(), e.getRawStatusCode());
        }
    }

    /**
     * Feature: PAAM - 2 (Application Registration)
     * Interface: PAAM - 3a
     * CommunicationType REST
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationUnegistrationOverRESTSuccess() throws JsonProcessingException {
        UserRegistrationRequest request = new UserRegistrationRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                new UserDetails(new Credentials("NewApplication", "NewPassword"), "", "", UserRole.APPLICATION));
        try {
            ResponseEntity<Void> response = restTemplate.postForEntity(serverAddress + unregistrationUri, request,
                    Void.class);
            assertEquals(HttpStatus.OK, response.getStatusCode());
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.BAD_REQUEST.value(), e.getRawStatusCode());
        }

    }

}