package eu.h2020.symbiote.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.*;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.commons.payloads.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.HttpClientErrorException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.TimeoutException;

import org.apache.commons.codec.binary.Base64;

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
    public void internalLoginRequestReplySuccessAndIssuesPlatformTokenType() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(username, password))
                .getBytes());
        RequestToken token = mapper.readValue(response, RequestToken.class);

        log.info("Test Client received this Token: " + token.toJson());

        assertNotNull(token.getToken());
        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
            assertEquals(IssuingAuthorityType.PLATFORM, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

            // verify that the token contains the application public key
            byte[] applicationPublicKeyInRepository = registrationManager.convertPEMToX509(userRepository.findOne(username).getCertificate().getPemCertificate()).getPublicKey().getEncoded();
            byte[] publicKeyFromToken = Base64.decodeBase64(claimsFromToken.getSpk());
            assertEquals(Arrays.equals(applicationPublicKeyInRepository,publicKeyFromToken),true);
        } catch (MalformedJWTException | JSONException | CertificateException e) {
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
    public void internalLoginRequestReplyMissingArguments() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(/* no username and/or
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
            String appUsername = "NewApplication";

            // verify that app is not in the repository
            User registeredUser = userRepository.findOne(appUsername);
            assertNull(registeredUser);

            /*
             XXX federated Id and recovery mail are required for Test AAM but not for Plaftorm AAM
             */
            // register new application to db
            UserRegistrationRequest userRegistrationRequest = new UserRegistrationRequest(new
                    Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials
                    (appUsername, "NewPassword"), "nullId", "nullMail", UserRole.APPLICATION));
            UserRegistrationResponse userRegistrationResponse = userRegistrationService.register
                    (userRegistrationRequest);

            // verify that app really is in repository
            registeredUser = userRepository.findOne(appUsername);
            assertNotNull(registeredUser);
            assertEquals(UserRole.APPLICATION, registeredUser.getRole());

            // verify that the server returns certificate & privateKey
            assertNotNull(userRegistrationResponse.getPemCertificate());
            assertNotNull(userRegistrationResponse.getPemPrivateKey());

            // TODO verify that released certificate has no CA property
        } catch (Exception e) {
            assertEquals(ExistingUserException.class, e.getClass());
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

            // TODO verify that released certificate has no CA property
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
            // verify that app really is in repository
            User user = userRepository.findOne(username);
            assertNotNull(user);

            // unregister
            userRegistrationService.unregister(username);
            log.debug("User successfully unregistered!");

            // verify that app is not anymore in the repository
            user = userRepository.findOne(username);
            assertNull(user);
        } catch (Exception e) {
            assertEquals(NotExistingUserException.class, e.getClass());
            log.error(e.getMessage());
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