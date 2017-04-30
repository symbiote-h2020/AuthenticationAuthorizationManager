package eu.h2020.symbiote.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.*;
import eu.h2020.symbiote.security.commons.json.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Test suite for Platform side AAM deployment scenarios.
 */
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
    public void internalLoginRequestReplySuccessAndIssuesRelevantTokenType() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new PlainCredentials(username, password))
                .getBytes());
        RequestToken token = mapper.readValue(response, RequestToken.class);

        log.info("Test Client received this Token: " + token.toJson());

        assertNotNull(token.getToken());
        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
            // for tests the token type should be set to NULL
            assertEquals(IssuingAuthorityType.NULL, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));
        } catch (MalformedJWTException | JSONException e) {
            e.printStackTrace();
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
    public void internalLoginRequestReplyWrongCredentials() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);

        byte[] response = client.primitiveCall(mapper.writeValueAsString(new PlainCredentials(wrongusername, password))
                .getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        byte[] response2 = client.primitiveCall(mapper.writeValueAsString(new PlainCredentials(username, wrongpassword))
                .getBytes());
        ErrorResponseContainer noToken2 = mapper.readValue(response2, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken2.getErrorMessage());

        byte[] response3 = client.primitiveCall(mapper.writeValueAsString(new PlainCredentials(wrongusername,
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
    public void internalLoginRequestReplyMissingArguments() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new PlainCredentials(/* no username and/or
        password */)).getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        assertEquals(new MissingArgumentsException().getErrorMessage(), noToken.getErrorMessage());
    }


    /**
     * Feature:
     * Interface: PAAM - 3a
     * CommunicationType REST
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void certificateCreationAndVerification() throws Exception {

        // UNA TANTUM - Generate Platform AAM Certificate and PV key and put that in a keystore
        //registrationManager.createSelfSignedAAMECCert();

        // Generate certificate for given application username (ie. "Daniele")
        KeyPair keyPair = registrationManager.createKeyPair();
        X509Certificate cert = registrationManager.createECCert("Daniele", keyPair.getPublic());

        // retrieves Platform AAM ("Daniele"'s certificate issuer) public key from keystore in order to verify
        // "Daniele"'s certificate
        cert.verify(registrationManager.getAAMPublicKey());

        // also check time validity
        cert.checkValidity(new Date());
    }


    /**
     * Feature: PAAM - 2 (Registration of a new application in the Platorm AAM)
     * Interface: PAAM - 3a
     * CommunicationType REST
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void successfulApplicationRegistration() throws Exception {
        try {
            // register new application to db
            ApplicationRegistrationRequest applicationRegistrationRequest = new ApplicationRegistrationRequest(new
                    PlainCredentials(AAMOwnerUsername, AAMOwnerPassword), new PlainCredentials
                    ("NewApplication", "NewPassword"), "", "");
            ApplicationRegistrationResponse applicationRegistrationResponse = applicationRegistrationService.register
                    (applicationRegistrationRequest);

            String cert = applicationRegistrationResponse.getPemCertificate();
            System.out.println(cert);
            X509Certificate certObj = registrationManager.convertPEMToX509(cert);
        } catch (Exception e) {
            assertEquals(ExistingApplicationException.class, e.getClass());
            log.info(e.getMessage());
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
    public void externalRegistrationSuccess() throws JsonProcessingException {
        ApplicationRegistrationRequest request = new ApplicationRegistrationRequest(
                new PlainCredentials(AAMOwnerUsername, AAMOwnerPassword),
                new PlainCredentials("NewApplication", "NewPassword"), "", "");
        try {
            ResponseEntity<ApplicationRegistrationResponse> response = restTemplate.postForEntity(serverAddress +
                    registrationUri, request, ApplicationRegistrationResponse.class);
            assertEquals(HttpStatus.OK, response.getStatusCode());
            log.info(response.getBody().toJson());
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
    public void successfulApplicationUnregistration() throws Exception {
        try {
            applicationRegistrationService.unregister(username);
            log.info("Application successfully unregistered!");
        } catch (Exception e) {
            assertEquals(NotExistingApplicationException.class, e.getClass());
            log.info(e.getMessage());
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
    public void externalUnregistrationSuccess() throws JsonProcessingException {
        ApplicationRegistrationRequest request = new ApplicationRegistrationRequest(
                new PlainCredentials(AAMOwnerUsername, AAMOwnerPassword),
                new PlainCredentials("NewApplication", "NewPassword"), "", "");
        try {
            ResponseEntity<Void> response = restTemplate.postForEntity(serverAddress + unregistrationUri, request,
                    Void.class);
            assertEquals(HttpStatus.OK, response.getStatusCode());
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.BAD_REQUEST.value(), e.getRawStatusCode());
        }

    }

}