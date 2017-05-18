package eu.h2020.symbiote.security.integration;

import com.fasterxml.jackson.core.JsonProcessingException;
import eu.h2020.symbiote.security.AuthenticationAuthorizationManagerTests;
import eu.h2020.symbiote.security.InternalSecurityHandler;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.exceptions.aam.MalformedJWTException;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.payloads.UserDetails;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import eu.h2020.symbiote.security.payloads.UserRegistrationResponse;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.HttpClientErrorException;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for Platform side AAM deployment scenarios.
 */
@TestPropertySource("/platform.properties")
public class PlatformAuthenticationAuthorizationManagerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(PlatformAuthenticationAuthorizationManagerTests.class);


    @Value("${rabbit.host}")
    protected String rabbitHost;
    @Value("${rabbit.username}")
    protected String rabbitUsername;
    @Value("${rabbit.password}")
    protected String rabbitPassword;

    /**
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1 and CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    @Ignore("We need to think how to initiate to local AAMs (a core and a platform one")
    public void applicationLoginOverAMQPSuccessAndIssuesCoreTokenType()
            throws IOException, TimeoutException, SecurityHandlerException {

        InternalSecurityHandler securityHandler =
                new InternalSecurityHandler(serverAddress, rabbitHost, rabbitUsername, rabbitPassword);
        Token token = securityHandler.requestFederatedCoreToken(username, password);

//        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
//        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(username, password))
//                .getBytes());
//        Token token = mapper.readValue(response, Token.class);

        assertNotNull(token.getToken());

        log.info("Test Client received this Token: " + token.toString());

        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
            assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

            // verify that the token contains the application public key
            byte[] applicationPublicKeyInRepository = userRepository.findOne
                    (username).getCertificate().getX509().getPublicKey().getEncoded();
            byte[] publicKeyFromToken = Base64.decodeBase64(claimsFromToken.getSpk());
            assertArrayEquals(applicationPublicKeyInRepository, publicKeyFromToken);
        } catch (MalformedJWTException | CertificateException e) {
            log.error(e);
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
    public void applicationRegistrationOverRESTSuccess() throws JsonProcessingException {
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
            assertNotNull(response.getBody().getUserCertificate());
            assertNotNull(response.getBody().getUserPrivateKey());
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
    public void applicationUnegistrationOverRESTSuccess() throws JsonProcessingException {
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