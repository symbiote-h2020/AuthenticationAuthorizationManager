package eu.h2020.symbiote;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.commons.Application;
import eu.h2020.symbiote.commons.RegistrationManager;
import eu.h2020.symbiote.commons.enums.Status;
import eu.h2020.symbiote.commons.exceptions.ExistingApplicationException;
import eu.h2020.symbiote.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.commons.exceptions.NotExistingApplicationException;
import eu.h2020.symbiote.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.commons.json.*;
import eu.h2020.symbiote.rabbitmq.RabbitManager;
import eu.h2020.symbiote.repositories.ApplicationRepository;
import eu.h2020.symbiote.services.ApplicationRegistrationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class AuthenticationAuthorizationManagerApplicationTests {

    private static Log log = LogFactory.getLog(AuthenticationAuthorizationManagerApplicationTests.class);
    private final String foreignTokenUri = "request_foreign_token";
    private final String checkHomeTokenRevocationUri = "check_home_token_revocation";
    private final String username = "testCloudAAMUser";
    private final String password = "testCloudAAMPass";
    private final String wrongusername = "veryWrongCloudAAMPass";
    private final String wrongpassword = "veryWrongCloudAAMPass";
    private final String homeTokenValue = "home_token_from_platform_aam-" + username;
    private final String tokenHeaderName = "X-Auth-Token";
    private final String loginUri = "login";
    private final String registrationUri = "register";
    private final String unregistrationUri = "unregister";
    @LocalServerPort
    private int port;
    @Autowired
    private ApplicationRepository applicationRepository;
    @Autowired
    private RabbitManager rabbitManager;
    @Autowired
    private RegistrationManager registrationManager;
    @Autowired
    private ApplicationRegistrationService applicationRegistrationService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    private RestTemplate restTemplate = new RestTemplate();
    private ObjectMapper mapper = new ObjectMapper();
    private String serverAddress;
    @Value("${rabbit.queue.login.request}")
    private String loginRequestQueue;
    @Value("${rabbit.queue.check_token_revocation.request}")
    private String checkTokenRevocationRequestQueue;

    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;

    @Value("${aam.security.KEY_STORE_PASSWORD}")
    private String KEY_STORE_PASSWORD;
    @Value("${aam.security.PV_KEY_STORE_PASSWORD}")
    private String PV_KEY_STORE_PASSWORD;
    @Value("${aam.security.KEY_STORE_FILE_NAME}")
    private String KEY_STORE_FILE_NAME;
    @Value("${aam.security.KEY_STORE_ALIAS}")
    private String KEY_STORE_ALIAS;

    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidityPeriod;

    @Before
    public void setUp() throws Exception {
        // Catch the random port
        serverAddress = "http://localhost:" + port + "/";
        // Test rest template
        restTemplate = new RestTemplate();
        // Insert username and password to DB
        Application application = new Application();
        application.setUsername(username);
        application.setPasswordEncrypted(passwordEncoder.encode(password));
        applicationRepository.save(application);
    }

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