package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AuthenticationAuthorizationManagerTests;
import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.aam.*;
import eu.h2020.symbiote.security.payloads.*;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
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
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1 and CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationLoginOverAMQPSuccessAndIssuesCoreTokenType() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(username, password))
                .getBytes());
        Token token = mapper.readValue(response, Token.class);

        log.info("Test Client received this Token: " + token.toString());

        assertNotNull(token.getToken());
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
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationLoginOverAMQPWrongCredentialsFailure() throws IOException, TimeoutException {

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
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationLoginOverAMQPMissingArgumentsFailure() throws IOException, TimeoutException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(/* no username and/or
        password */)).getBytes());
        ErrorResponseContainer noToken = mapper.readValue(response, ErrorResponseContainer.class);

        log.info("Test Client received this error message instead of token: " + noToken.getErrorMessage());

        assertEquals(new MissingArgumentsException().getErrorMessage(), noToken.getErrorMessage());
    }


    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interface: PAAM - 2, CAAM - 1
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void checkTokenRevocationOverAMQPRequestReplyValid() throws IOException, TimeoutException,
            TokenValidationException {

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(AAMConstants.TOKEN_HEADER_NAME));
        String token = headers.getFirst(AAMConstants.TOKEN_HEADER_NAME);

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                checkTokenRevocationRequestQueue,
                10000);
        byte[] amqpResponse = client.primitiveCall(mapper.writeValueAsString(new Token(token)).getBytes());
        CheckRevocationResponse checkRevocationResponse = mapper.readValue(amqpResponse,
                CheckRevocationResponse.class);

        log.info("Test Client received this TokenValidationStatus: " + checkRevocationResponse.toJson());

        assertEquals(ValidationStatus.VALID.toString(), checkRevocationResponse.getStatus());
    }


    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void userLoginOverRESTWrongUsernameFailure() {
        ResponseEntity<ErrorResponseContainer> token = null;
        try {
            token = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN, new Credentials(wrongusername,
                            password),
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
    public void userLoginOverRESTWrongPasswordFailure() {
        ResponseEntity<ErrorResponseContainer> token = null;
        try {
            token = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN, new Credentials(username,
                            wrongpassword),
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
    public void applicationLoginOverRESTSuccessAndIssuesCoreTokenWithoutPOAttributes() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(AAMConstants.TOKEN_HEADER_NAME));
        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(AAMConstants.TOKEN_HEADER_NAME));
            // As the AAM is now configured as core we confirm that relevant token type was issued.
            assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

            // verify that this JWT contains attributes relevant for application role
            Map<String, String> attributes = claimsFromToken.getAtt();
            assertEquals(UserRole.APPLICATION.toString(), attributes.get(CoreAttributes.ROLE.toString()));

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
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */
    @Test
    public void foreignTokenRequestOverRESTFailsForHomeTokenUsedAsRequest() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(AAMConstants.TOKEN_HEADER_NAME, loginHeaders.getFirst(AAMConstants.TOKEN_HEADER_NAME));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        try {
            restTemplate.postForEntity(serverAddress + AAMConstants
                            .AAM_REQUEST_FOREIGN_TOKEN, request,
                    String.class);
            assert false;
        } catch (RestClientException e) {
            // TODO think of a better way to assert that BAD_REQUEST
            log.error(e);
            assertNotNull(e);
        }

    }

    /**
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */
    @Test
    @Ignore("We need to think how to initiate to local AAMs (a core and a platform one")
    public void foreignTokenRequestOverRESTSuccess() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(AAMConstants.TOKEN_HEADER_NAME, loginHeaders.getFirst(AAMConstants.TOKEN_HEADER_NAME));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<String> responseToken = restTemplate.postForEntity(serverAddress + AAMConstants
                        .AAM_REQUEST_FOREIGN_TOKEN, request,
                String.class);
        HttpHeaders rspHeaders = responseToken.getHeaders();

        assertEquals(HttpStatus.OK, responseToken.getStatusCode());
        assertNotNull(rspHeaders.getFirst(AAMConstants.TOKEN_HEADER_NAME));
    }

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
    @Test
    public void checkTokenRevocationOverRESTValid() {

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(AAMConstants.TOKEN_HEADER_NAME, loginHeaders.getFirst(AAMConstants.TOKEN_HEADER_NAME));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<CheckRevocationResponse> status = restTemplate.postForEntity(serverAddress +
                AAMConstants.AAM_CHECK_HOME_TOKEN_REVOCATION, request, CheckRevocationResponse.class);

        assertEquals(ValidationStatus.VALID.toString(), status.getBody().getStatus());
    }

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
    @Test
    public void checkTokenRevocationOverRESTExpired() {

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        //Introduce latency so that JWT expires
        try {
            Thread.sleep(tokenValidityPeriod + 1000);
        } catch (InterruptedException e) {
            log.error(e);
        }
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(AAMConstants.TOKEN_HEADER_NAME, loginHeaders.getFirst(AAMConstants.TOKEN_HEADER_NAME));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<CheckRevocationResponse> status = restTemplate.postForEntity(serverAddress +
                AAMConstants.AAM_CHECK_HOME_TOKEN_REVOCATION, request, CheckRevocationResponse.class);

        // TODO cover other situations (bad key, on purpose revocation)
        assertEquals(ValidationStatus.EXPIRED.toString(), status.getBody().getStatus());
    }

    /**
     * Feature: User Repository
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationInternalRegistrationSuccess() throws Exception {
        try {
            String appUsername = "NewApplication";

            // verify that app is not in the repository
            User registeredUser = userRepository.findOne(appUsername);
            assertNull(registeredUser);

            /*
             XXX federated Id and recovery mail are required for Test & Core AAM but not for Plaftorm AAM
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
            assertNotNull(userRegistrationResponse.getUserCertificate());
            assertNotNull(userRegistrationResponse.getUserPrivateKey());

            // TODO verify that released certificate has no CA property
        } catch (Exception e) {
            assertEquals(ExistingUserException.class, e.getClass());
            log.info(e.getMessage());
        }
    }


    /**
     * Feature: User Repository
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void applicationInternalUnregistrationSuccess() throws Exception {
        try {
            // verify that app really is in repository
            User user = userRepository.findOne(username);
            assertNotNull(user);

            // get user certficate
            Certificate userCertificate = user.getCertificate();
            // verify the certificate is not yet revoked
            assertFalse(revokedCertificatesRepository.exists(userCertificate.toString()));

            // unregister
            userRegistrationService.unregister(username);
            log.debug("User successfully unregistered!");

            // verify that app is not anymore in the repository
            assertFalse(userRepository.exists(username));
            // verify that the user certificate was indeed revoked
            assertTrue(revokedCertificatesRepository.exists(userCertificate.toString()));
        } catch (Exception e) {
            assertEquals(NotExistingUserException.class, e.getClass());
            log.error(e.getMessage());
        }
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
     * Features: CAAM - 12 (AAM as a CA)
     * Interfaces: CAAM - 15;
     * CommunicationType REST
     */
    @Test
    public void getCACertOverRESTSuccess() {
        ResponseEntity<String> response = restTemplate.getForEntity(serverAddress + AAMConstants
                .AAM_GET_CA_CERTIFICATE, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        try {
            assertEquals(registrationManager.getAAMCert(), response.getBody());
        } catch (IOException | NoSuchProviderException | KeyStoreException | CertificateException |
                NoSuchAlgorithmException e) {
            log.error(e);
            assertNull(e);
        }
    }
}