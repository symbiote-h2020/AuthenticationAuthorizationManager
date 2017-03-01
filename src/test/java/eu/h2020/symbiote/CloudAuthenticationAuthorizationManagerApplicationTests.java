package eu.h2020.symbiote;

import static org.junit.Assert.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.rabbitmq.RabbitManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import eu.h2020.symbiote.commons.enums.Status;
import eu.h2020.symbiote.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.commons.json.ErrorResponseContainer;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.model.UserModel;
import eu.h2020.symbiote.repositories.UserRepository;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

@RunWith(SpringRunner.class)
//@SpringBootTest({"webEnvironment = WebEnvironment.RANDOM_PORT", "eureka.client.enabled=false"}) // FIXME: DOESN'T WORK WITH MULTIPLE PROPERTIES
@SpringBootTest(webEnvironment=WebEnvironment.RANDOM_PORT)
public class CloudAuthenticationAuthorizationManagerApplicationTests {

	@Autowired
	private UserRepository userRepository;

	@LocalServerPort
	int port;

	private static Log log = LogFactory.getLog(CloudAuthenticationAuthorizationManagerApplicationTests.class);

	RestTemplate restTemplate = new RestTemplate();

	@Autowired
    private RabbitTemplate rabbitTemplate;

	@Autowired
	private RabbitManager rabbitManager;


	private String serverAddress;
	private final String loginUri = "login";
	private final String foreignTokenUri = "request_foreign_token";
	private final String checkHomeTokenRevocationUri = "check_home_token_revocation";

	private final String username = "testCloudAAMUser";
	private final String password = "testCloudAAMPass";

	private final String wrongusername = "veryWrongCloudAAMPass";
	private final String wrongpassword = "veryWrongCloudAAMPass";

	private final String homeTokenValue = "home_token_from_platform_aam";
	private final String foreignTokenValue = "foreign_token_from_platform_aam";

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
		ResponseEntity<RequestToken> token = restTemplate.postForEntity(serverAddress + loginUri,
				new LoginRequest(username, password), RequestToken.class);
		assertEquals(token.getStatusCode(), HttpStatus.OK);
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
		ResponseEntity<RequestToken> token = restTemplate.postForEntity(serverAddress + foreignTokenUri,
				new RequestToken(homeTokenValue), RequestToken.class);
		assertEquals(token.getBody().getToken(), foreignTokenValue);
	}
	
	@Test
	public void externalCheckTokenRevocation() {
		ResponseEntity<CheckTokenRevocationResponse> status = restTemplate.postForEntity(serverAddress + checkHomeTokenRevocationUri,
				new RequestToken(homeTokenValue), CheckTokenRevocationResponse.class);
		assertEquals(status.getBody().getStatus(), Status.SUCCESS.toString());
	}

	@Test
	public void internalLoginRequestReplySuccess() throws IOException, TimeoutException {

		ObjectMapper mapper = new ObjectMapper();

		RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
		byte[] response = client.primitiveCall(mapper.writeValueAsString(new LoginRequest(username, password)).getBytes());
		RequestToken token = mapper.readValue(response, RequestToken.class);

		log.info("Test Client received this Token: " + token.toJson());

		assertEquals(homeTokenValue, token.getToken());
	}

    @Test
    public void internalCheckTokenRevocationRequestReplySuccess() throws IOException, TimeoutException {

        ObjectMapper mapper = new ObjectMapper();

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", checkTokenRevocationRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new RequestToken(homeTokenValue)).getBytes());
        CheckTokenRevocationResponse checkTokenRevocationResponse = mapper.readValue(response, CheckTokenRevocationResponse.class);

        log.info("Test Client received this Status: " + checkTokenRevocationResponse.toJson());

        assertEquals(Status.SUCCESS.toString(), checkTokenRevocationResponse.getStatus());
    }

}