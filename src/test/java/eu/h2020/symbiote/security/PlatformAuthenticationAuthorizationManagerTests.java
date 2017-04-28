package eu.h2020.symbiote.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.exceptions.ExistingApplicationException;
import eu.h2020.symbiote.security.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.NotExistingApplicationException;
import eu.h2020.symbiote.security.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.json.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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


    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    @Ignore("JWT ttyp Not yet implemented")
    public void externalLoginIssuesCoreToken() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new PlainCredentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(response.getStatusCode(), HttpStatus.OK);
        assertNotEquals(headers.getFirst(tokenHeaderName), null);
        // TODO: check if JWT ttyp field is set to HOME
    }


    /**
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1
     * CommunicationType AMQP
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    @Ignore("JWT ttyp Not yet implemented")
    public void internalLoginRequestReplySuccess() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new PlainCredentials(username, password))
                .getBytes());
        RequestToken token = mapper.readValue(response, RequestToken.class);

        log.info("Test Client received this Token: " + token.toJson());

        assertNotEquals(token.getToken(), null);
        // TODO: check if JWT ttyp field is set to HOME
    }

    /**
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1
     * CommunicationType AMQP
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
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void successfulApplicationRegistration() throws Exception {
        try {
            // register new application to db
            RegistrationResponse registrationResponse = applicationRegistrationService.register(new PlainCredentials
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

    /**
     * Feature: PAAM - 2 (Application Registration)
     * Interface: PAAM - 3a
     * CommunicationType REST
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void externalRegistrationSuccess() throws JsonProcessingException {
        RegistrationRequest request = new RegistrationRequest(
                new PlainCredentials(AAMOwnerUsername, AAMOwnerPassword),
                new PlainCredentials("NewApplication", "NewPassword"));
        try {
            ResponseEntity<RegistrationResponse> response = restTemplate.postForEntity(serverAddress +
                    registrationUri, request, RegistrationResponse.class);
            assertEquals(response.getStatusCode(), HttpStatus.OK);
            log.info(response.getBody().toJson());
        } catch (HttpClientErrorException e) {
            assertEquals(e.getRawStatusCode(), HttpStatus.BAD_REQUEST.value());
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
            applicationRegistrationService.unregister(new PlainCredentials("NewApplication", "NewPassword"));
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
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void externalUnregistrationSuccess() throws JsonProcessingException {
        RegistrationRequest request = new RegistrationRequest(
                new PlainCredentials(AAMOwnerUsername, AAMOwnerPassword),
                new PlainCredentials("NewApplication", "NewPassword"));
        try {
            ResponseEntity<Void> response = restTemplate.postForEntity(serverAddress + unregistrationUri, request,
                    Void.class);
            assertEquals(response.getStatusCode(), HttpStatus.OK);
        } catch (HttpClientErrorException e) {
            assertEquals(e.getRawStatusCode(), HttpStatus.BAD_REQUEST.value());
        }

    }

}