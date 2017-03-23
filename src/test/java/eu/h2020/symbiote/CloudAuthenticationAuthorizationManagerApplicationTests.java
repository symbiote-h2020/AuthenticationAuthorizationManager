package eu.h2020.symbiote;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

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
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.RpcClient;

import eu.h2020.symbiote.commons.enums.Status;
import eu.h2020.symbiote.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.commons.json.ErrorResponseContainer;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.model.UserModel;
import eu.h2020.symbiote.rabbitmq.RabbitManager;
import eu.h2020.symbiote.repositories.UserRepository;

@RunWith(SpringRunner.class)
//@SpringBootTest({"webEnvironment = WebEnvironment.RANDOM_PORT", "eureka.client.enabled=false"}) // FIXME: DOESN'T WORK WITH MULTIPLE PROPERTIES
@SpringBootTest(webEnvironment=WebEnvironment.RANDOM_PORT)
public class CloudAuthenticationAuthorizationManagerApplicationTests {

	private static Log log = LogFactory.getLog(CloudAuthenticationAuthorizationManagerApplicationTests.class);

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RabbitManager rabbitManager;

	@LocalServerPort
	int port;

	private RestTemplate restTemplate = new RestTemplate();
	private ObjectMapper mapper = new ObjectMapper();

	private String serverAddress;
	private final String loginUri = "login";
	private final String foreignTokenUri = "request_foreign_token";
	private final String checkHomeTokenRevocationUri = "check_home_token_revocation";

	private final String username = "testCloudAAMUser";
	private final String password = "testCloudAAMPass";

	private final String wrongusername = "veryWrongCloudAAMPass";
	private final String wrongpassword = "veryWrongCloudAAMPass";

	private final String homeTokenValue = "home_token_from_platform_aam-"+username;
	private final String foreignTokenValue = "foreign_token_from_platform_aam-"+homeTokenValue;

	private final String tokenHeaderName = "X-Auth-Token";
    
	@Value("${rabbit.queue.login.request}")
	private String loginRequestQueue;
    @Value("${rabbit.queue.check_token_revocation.request}")
    private String checkTokenRevocationRequestQueue;


	@Before
	public void setUp() throws Exception {
		// Catch the random port
		serverAddress = "http://localhost:" + port + "/";
		// Test rest template
		restTemplate = new RestTemplate();
		// Insert username and password to DB
		userRepository.save(new UserModel(username, password));
	}

	@Test
	public void externalLoginSuccess() {
		ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
				new LoginRequest(username, password),String.class);
		HttpHeaders headers = response.getHeaders();
		assertEquals(response.getStatusCode(), HttpStatus.OK);
		assertEquals(headers.getFirst(tokenHeaderName),homeTokenValue);
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
		
		MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
		headers.add(tokenHeaderName, homeTokenValue);

		HttpEntity<String> request = new HttpEntity<String>(null, headers);

		ResponseEntity<String> responseToken = restTemplate.postForEntity(serverAddress + foreignTokenUri, request, String.class);
		HttpHeaders rspHeaders = responseToken.getHeaders();
		
		assertEquals(responseToken.getStatusCode(), HttpStatus.OK);
		assertEquals(rspHeaders.getFirst(tokenHeaderName),foreignTokenValue);
	}
	
	@Test
	public void externalCheckTokenRevocation() {
		MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
		headers.add(tokenHeaderName, homeTokenValue);

		HttpEntity<String> request = new HttpEntity<String>(null, headers);
		
		ResponseEntity<CheckTokenRevocationResponse> status = restTemplate.postForEntity(serverAddress + checkHomeTokenRevocationUri, request, CheckTokenRevocationResponse.class);
		
		assertEquals(status.getBody().getStatus(), Status.SUCCESS.toString());
	}

	@Test
	public void internalLoginRequestReplySuccess() throws IOException, TimeoutException {

		RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
		byte[] response = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(username, password)).getBytes());
		RequestToken token = mapper.readValue(response, RequestToken.class);

		log.info("Test Client received this Token: " + token.toJson());

		assertEquals(homeTokenValue, token.getToken());
	}

	@Test
	public void internalLoginRequestReplyWrongCredentials() throws IOException, TimeoutException {

		RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);

		byte[] response = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(wrongusername, password)).getBytes());
		ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

		log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

		byte[] response2 = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(username, wrongpassword)).getBytes());
		ErrorResponseContainer noToken2 = mapper.readValue(response2, ErrorResponseContainer.class);

		log.info("Test Client received this error message instead of token: " + noToken2.getErrorMessage());

		byte[] response3 = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(wrongusername, wrongpassword)).getBytes());
		ErrorResponseContainer noToken3 = mapper.readValue(response3, ErrorResponseContainer.class);

		log.info("Test Client received this error message instead of token: " + noToken3.getErrorMessage());

		String expectedErrorMessage = new WrongCredentialsException().getErrorMessage();

		assertEquals(expectedErrorMessage,  noToken.getErrorMessage());
		assertEquals(expectedErrorMessage, noToken2.getErrorMessage());
		assertEquals(expectedErrorMessage, noToken3.getErrorMessage());
	}

	@Test
	public void internalLoginRequestReplyMissingArguments() throws IOException, TimeoutException {

		RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
		byte[] response = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(/* no username and/or password */)).getBytes());
		ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

		log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

		assertEquals(new MissingArgumentsException().getErrorMessage(), noToken.getErrorMessage());
	}

    @Test
    public void internalCheckTokenRevocationRequestReplySuccess() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", checkTokenRevocationRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new RequestToken(homeTokenValue)).getBytes());
        CheckTokenRevocationResponse checkTokenRevocationResponse = mapper.readValue(response, CheckTokenRevocationResponse.class);

        log.info("Test Client received this Status: " + checkTokenRevocationResponse.toJson());

        assertEquals(Status.SUCCESS.toString(), checkTokenRevocationResponse.getStatus());
    }

}