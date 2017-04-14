package eu.h2020.symbiote.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.enums.Status;
import eu.h2020.symbiote.security.commons.exceptions.ExistingApplicationException;
import eu.h2020.symbiote.security.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.NotExistingApplicationException;
import eu.h2020.symbiote.security.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.json.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * Test suite for Platform side AAM deployment scenarios.
 */
public class PlatformAuthenticationAuthorizationManagerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(PlatformAuthenticationAuthorizationManagerTests.class);

    @Test
    public void externalLoginSuccess() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new LoginRequest(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(response.getStatusCode(), HttpStatus.OK);
        assertNotEquals(headers.getFirst(tokenHeaderName), null);
    }

    @Test
    public void externalLoginWrongUsername() {
        ResponseEntity<ErrorResponseContainer> token = null;
        try {
            token = restTemplate.postForEntity(serverAddress + loginUri, new LoginRequest(wrongusername, password),
                    ErrorResponseContainer.class);
        } catch (HttpClientErrorException e) {
            assertEquals(token, null);
            assertEquals(e.getRawStatusCode(), HttpStatus.UNAUTHORIZED.value());
        }

    }

    @Test
    public void externalLoginWrongPassword() {
        ResponseEntity<ErrorResponseContainer> token = null;
        try {
            token = restTemplate.postForEntity(serverAddress + loginUri, new LoginRequest(username, wrongpassword),
                    ErrorResponseContainer.class);
        } catch (HttpClientErrorException e) {
            assertEquals(token, null);
            assertEquals(e.getRawStatusCode(), HttpStatus.UNAUTHORIZED.value());
        }
    }

    @Test
    public void externalRequestForeignToken() {

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new LoginRequest(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(tokenHeaderName, loginHeaders.getFirst(tokenHeaderName));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<String> responseToken = restTemplate.postForEntity(serverAddress + foreignTokenUri, request,
                String.class);
        HttpHeaders rspHeaders = responseToken.getHeaders();

        assertEquals(responseToken.getStatusCode(), HttpStatus.OK);
        assertNotEquals(rspHeaders.getFirst(tokenHeaderName), null);
    }

    @Test
    public void externalCheckTokenRevocationSucess() {

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new LoginRequest(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(tokenHeaderName, loginHeaders.getFirst(tokenHeaderName));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<CheckTokenRevocationResponse> status = restTemplate.postForEntity(serverAddress +
                checkHomeTokenRevocationUri, request, CheckTokenRevocationResponse.class);

        assertEquals(status.getBody().getStatus(), Status.SUCCESS.toString());
    }

    @Test
    public void externalCheckTokenRevocationFailure() {

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new LoginRequest(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        //Introduce latency so that JWT expires
        try {
            Thread.sleep(tokenValidityPeriod * 2);
        } catch (InterruptedException e) {
        }
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(tokenHeaderName, loginHeaders.getFirst(tokenHeaderName));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<CheckTokenRevocationResponse> status = restTemplate.postForEntity(serverAddress +
                checkHomeTokenRevocationUri, request, CheckTokenRevocationResponse.class);

        assertEquals(status.getBody().getStatus(), Status.FAILURE.toString());
    }

    @Test
    public void internalLoginRequestReplySuccess() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(username, password))
                .getBytes());
        RequestToken token = mapper.readValue(response, RequestToken.class);

        log.info("Test Client received this Token: " + token.toJson());

        assertNotEquals(token.getToken(), null);
    }

    @Test
    public void internalLoginRequestReplyWrongCredentials() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);

        byte[] response = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(wrongusername, password))
                .getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        byte[] response2 = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(username, wrongpassword))
                .getBytes());
        ErrorResponseContainer noToken2 = mapper.readValue(response2, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken2.getErrorMessage());

        byte[] response3 = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(wrongusername,
                wrongpassword)).getBytes());
        ErrorResponseContainer noToken3 = mapper.readValue(response3, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken3.getErrorMessage());

        String expectedErrorMessage = new WrongCredentialsException().getErrorMessage();

        assertEquals(expectedErrorMessage, noToken.getErrorMessage());
        assertEquals(expectedErrorMessage, noToken2.getErrorMessage());
        assertEquals(expectedErrorMessage, noToken3.getErrorMessage());
    }

    @Test
    public void internalLoginRequestReplyMissingArguments() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(/* no username and/or
        password */)).getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        assertEquals(new MissingArgumentsException().getErrorMessage(), noToken.getErrorMessage());
    }

    @Test
    public void internalCheckTokenRevocationRequestReplySuccess() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(username, password))
                .getBytes());
        RequestToken testToken = mapper.readValue(response, RequestToken.class);

        client = new RpcClient(rabbitManager.getConnection().createChannel(), "", checkTokenRevocationRequestQueue,
                10000);
        response = client.primitiveCall(mapper.writeValueAsString(new RequestToken(testToken.getToken())).getBytes());
        CheckTokenRevocationResponse checkTokenRevocationResponse = mapper.readValue(response,
                CheckTokenRevocationResponse.class);

        log.info("Test Client received this Status: " + checkTokenRevocationResponse.toJson());

        assertEquals(Status.SUCCESS.toString(), checkTokenRevocationResponse.getStatus());
    }

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

    @Test
    public void successfulApplicationRegistration() throws Exception {
        try {
            // register new application to db
            RegistrationResponse registrationResponse = applicationRegistrationService.register(new LoginRequest
                    ("NewApplication", "NewPassword"));
            String cert = registrationResponse.getPemCertificate();
            System.out.println(cert);
            X509Certificate certObj = registrationManager.convertPEMToX509(cert);
            int a = 0;
        } catch (Exception e) {
            assertEquals(ExistingApplicationException.class, e.getClass());
            log.info(e.getMessage());
        }

    }

    @Test

    public void externalRegistrationSuccess() throws JsonProcessingException {
        RegistrationRequest request = new RegistrationRequest(
                new LoginRequest(AAMOwnerUsername, AAMOwnerPassword),
                new LoginRequest("NewApplication", "NewPassword"));
        try {
            ResponseEntity<RegistrationResponse> response = restTemplate.postForEntity(serverAddress +
                    registrationUri, request, RegistrationResponse.class);
            assertEquals(response.getStatusCode(), HttpStatus.OK);
            log.info(response.getBody().toJson());
        } catch (HttpClientErrorException e) {
            assertEquals(e.getRawStatusCode(), HttpStatus.BAD_REQUEST.value());
        }
    }

    @Test
    public void successfulApplicationUnregistration() throws Exception {
        try {
            applicationRegistrationService.unregister(new LoginRequest("NewApplication", "NewPassword"));
            log.info("Application successfully unregistered!");
        } catch (Exception e) {
            assertEquals(NotExistingApplicationException.class, e.getClass());
            log.info(e.getMessage());
        }
    }

    @Test
    public void externalUnregistrationSuccess() throws JsonProcessingException {
        RegistrationRequest request = new RegistrationRequest(
                new LoginRequest(AAMOwnerUsername, AAMOwnerPassword),
                new LoginRequest("NewApplication", "NewPassword"));
        try {
            ResponseEntity<Void> response = restTemplate.postForEntity(serverAddress + unregistrationUri, request,
                    Void.class);
            assertEquals(response.getStatusCode(), HttpStatus.OK);
        } catch (HttpClientErrorException e) {
            assertEquals(e.getRawStatusCode(), HttpStatus.BAD_REQUEST.value());
        }

    }

}