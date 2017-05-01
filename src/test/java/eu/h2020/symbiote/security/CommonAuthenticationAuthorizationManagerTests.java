package eu.h2020.symbiote.security;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.Status;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.MalformedJWTException;
import eu.h2020.symbiote.security.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.security.commons.json.Credentials;
import eu.h2020.symbiote.security.commons.json.ErrorResponseContainer;
import eu.h2020.symbiote.security.commons.json.RequestToken;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.commons.jwt.attributes.CoreAttributes;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for generic AAM functionality irrelevant to actual deployment type (Core or Platform)
 */
@TestPropertySource("/core.properties")
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

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new Credentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(tokenHeaderName));
        String token = headers.getFirst(tokenHeaderName);

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", checkTokenRevocationRequestQueue,
                10000);
        byte[] amqpResponse = client.primitiveCall(mapper.writeValueAsString(new RequestToken(token)).getBytes());
        CheckTokenRevocationResponse checkTokenRevocationResponse = mapper.readValue(amqpResponse,
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
    public void externalLoginWrongUsername() {
        ResponseEntity<ErrorResponseContainer> token = null;
        try {
            token = restTemplate.postForEntity(serverAddress + loginUri, new Credentials(wrongusername, password),
                    ErrorResponseContainer.class);
        } catch (HttpClientErrorException e) {
            assertNull(token);
            assertEquals(HttpStatus.UNAUTHORIZED.value(), e.getRawStatusCode());
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
            token = restTemplate.postForEntity(serverAddress + loginUri, new Credentials(username, wrongpassword),
                    ErrorResponseContainer.class);
        } catch (HttpClientErrorException e) {
            assertNull(token);
            assertEquals(HttpStatus.UNAUTHORIZED.value(), e.getRawStatusCode());
        }
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void externalLoginSuccess() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new Credentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(tokenHeaderName));
        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(tokenHeaderName));
            // As the AAM is now configured as core we confirm that relevant token type was issued.
            assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

            // verify that this JWT contains attributes relevant for application owner
            Map<String, String> attributes = claimsFromToken.getAtt();
            // PO role
            assertEquals(UserRole.APPLICATION.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        } catch (MalformedJWTException | JSONException e) {
            e.printStackTrace();
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
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(tokenHeaderName, loginHeaders.getFirst(tokenHeaderName));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<String> responseToken = restTemplate.postForEntity(serverAddress + foreignTokenUri, request,
                String.class);
        HttpHeaders rspHeaders = responseToken.getHeaders();

        assertEquals(HttpStatus.OK, responseToken.getStatusCode());
        assertNotNull(rspHeaders.getFirst(tokenHeaderName));
    }

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
    @Test
    public void externalCheckTokenRevocationSuccess() {

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(tokenHeaderName, loginHeaders.getFirst(tokenHeaderName));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<CheckTokenRevocationResponse> status = restTemplate.postForEntity(serverAddress +
                checkHomeTokenRevocationUri, request, CheckTokenRevocationResponse.class);

        assertEquals(Status.SUCCESS.toString(), status.getBody().getStatus());
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
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        //Introduce latency so that JWT expires
        try {
            Thread.sleep(tokenValidityPeriod + 1000);
        } catch (InterruptedException e) {
            log.error(e);
        }
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(tokenHeaderName, loginHeaders.getFirst(tokenHeaderName));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<CheckTokenRevocationResponse> status = restTemplate.postForEntity(serverAddress +
                checkHomeTokenRevocationUri, request, CheckTokenRevocationResponse.class);

        assertEquals(Status.FAILURE.toString(), status.getBody().getStatus());
    }


}