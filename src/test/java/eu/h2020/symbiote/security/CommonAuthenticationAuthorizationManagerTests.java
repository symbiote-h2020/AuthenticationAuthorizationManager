package eu.h2020.symbiote.security;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.enums.Status;
import eu.h2020.symbiote.security.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.security.commons.json.ErrorResponseContainer;
import eu.h2020.symbiote.security.commons.json.LoginRequest;
import eu.h2020.symbiote.security.commons.json.RequestToken;
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
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * Test suite for generic AAM functionality irrelevant to actual deployment type (Core or Platform)
 */
public class CommonAuthenticationAuthorizationManagerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CommonAuthenticationAuthorizationManagerTests.class);


    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interface: PAAM - 2, CAAM - 1
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
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


    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void externalLoginSuccess() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new LoginRequest(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(response.getStatusCode(), HttpStatus.OK);
        assertNotEquals(headers.getFirst(tokenHeaderName), null);
    }


    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
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

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
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

    /**
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */
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

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
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

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
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

}