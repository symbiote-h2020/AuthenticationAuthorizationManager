package eu.h2020.symbiote;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
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

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { CloudAuthenticationAuthorizationManagerApplication.class })
@SpringBootTest({ "eureka.client.enabled=false" })
public class CloudAuthenticationAuthorizationManagerApplicationTests {

	@Autowired
	private UserRepository userRepository;

	RestTemplate restTemplate = new RestTemplate();

	private final String serverAddress = "http://localhost:8300/";
	private final String loginUri = "login";
	private final String foreignTokenUri = "request_foreign_token";
	private final String checkHomeTokenRevocationUri = "check_home_token_revocation";

	private final String username = "testCloudAAMUser";
	private final String password = "testCloudAAMPass";

	private final String wrongusername = "veryWrongCloudAAMPass";
	private final String wrongpassword = "veryWrongCloudAAMPass";

	private final String homeTokenValue = "home_token_from_platform_aam";
	private final String foreignTokenValue = "foreign_token_from_platform_aam";

	@Before
	public void setUp() throws Exception {
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

}