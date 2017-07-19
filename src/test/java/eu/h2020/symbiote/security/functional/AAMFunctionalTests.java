package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.CoreAttributes;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.interfaces.payloads.ValidationRequest;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
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

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static io.jsonwebtoken.impl.crypto.RsaProvider.generateKeyPair;
import static org.junit.Assert.*;

/**
 * Test suite for generic AAM functionality irrelevant to actual deployment type (Core or Platform)
 */
@TestPropertySource("/core.properties")
public class AAMFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(AAMFunctionalTests.class);

    /**
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1 and CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void userLoginOverAMQPSuccessAndIssuesCoreTokenType() throws IOException, TimeoutException,
            MalformedJWTException {

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response = client.primitiveCall(mapper.writeValueAsString(new Credentials(username, password))
                .getBytes());
        Token token = mapper.readValue(response, Token.class);

        log.info("Test Client received this Token: " + token.toString());

        // check if token received
        assertNotNull(token);
        // check if issuing authority is core
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
        assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));
    }


    /**
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void userLoginOverAMQPWrongCredentialsFailure() throws IOException, TimeoutException {

        // test combinations of wrong credentials
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
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    public void userLoginOverAMQPMissingArgumentsFailure() throws IOException, TimeoutException {

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
    public void validationOverAMQPRequestReplyValid() throws IOException, TimeoutException,
            ValidationException {

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants
                        .AAM_GET_HOME_TOKEN,
                new Credentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        String token = headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME);

        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                validateRequestQueue,
                10000);
        byte[] amqpResponse = client.primitiveCall(mapper.writeValueAsString(new ValidationRequest(token, "")).getBytes());
        ValidationStatus validationStatus = mapper.readValue(amqpResponse,
                ValidationStatus.class);

        log.info("Test Client received this ValidationStatus: " + validationStatus);

        assertEquals(ValidationStatus.VALID, validationStatus);
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
            token = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN, new Credentials
                            (wrongusername,
                            password),
                    ErrorResponseContainer.class);
            assert false;
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
            token = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN, new Credentials
                            (username,
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
     * TODO getting certificate
     */
    @Test
    public void userLoginOverRESTSuccessAndIssuesCoreTokenWithoutPOAttributes() throws CertificateException,
            MalformedJWTException {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN,
                new Credentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        // As the AAM is now configured as core we confirm that relevant token type was issued.
        assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

        // verify that this JWT contains attributes relevant for user role
        Map<String, String> attributes = claimsFromToken.getAtt();
        assertEquals(UserRole.USER.toString(), attributes.get(CoreAttributes.ROLE.toString()));

        // verify that the token contains the user public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (username).getClientCertificates().entrySet().iterator().next().getValue().getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.decodeBase64(claimsFromToken.getSpk());

        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);
    }

    /**
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */
    @Test
    public void federatedTokenRequestOverRESTFailsForHomeTokenUsedAsRequest() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN,
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(SecurityConstants.TOKEN_HEADER_NAME, loginHeaders.getFirst(SecurityConstants.TOKEN_HEADER_NAME));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        try {
            restTemplate.postForEntity(serverAddress + SecurityConstants
                            .AAM_GET_FOREIGN_TOKEN, request,
                    String.class);
            assert false;
        } catch (RestClientException e) {
            // TODO think of a better way to assert that BAD_REQUEST
            log.error(e);
            assertNotNull(e);
        }

    }

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
    @Test
    public void validationOverRESTValid() {

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN,
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(SecurityConstants.TOKEN_HEADER_NAME, loginHeaders.getFirst(SecurityConstants.TOKEN_HEADER_NAME));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<ValidationStatus> status = restTemplate.postForEntity(serverAddress +
                SecurityConstants.AAM_VALIDATE, request, ValidationStatus.class);

        assertEquals(ValidationStatus.VALID, status.getBody());
    }

    /**
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
    @Test
    public void validationOverRESTExpired() throws InterruptedException {

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_HOME_TOKEN,
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();

        //Introduce latency so that JWT expires
        Thread.sleep(tokenValidityPeriod + 1000);
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(SecurityConstants.TOKEN_HEADER_NAME, loginHeaders.getFirst(SecurityConstants.TOKEN_HEADER_NAME));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<ValidationStatus> status = restTemplate.postForEntity(serverAddress +
                SecurityConstants.AAM_VALIDATE, request, ValidationStatus.class);

        // TODO cover other situations (bad key, on purpose revocation)
        assertEquals(ValidationStatus.EXPIRED_TOKEN, status.getBody());
    }


    /**
     * Features: CAAM - 12 (AAM as a CA)
     * Interfaces: CAAM - 15;
     * CommunicationType REST
     */
    @Test
    public void getComponentCertificateOverRESTSuccess() throws NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException, KeyStoreException, IOException {
        ResponseEntity<String> response = restTemplate.getForEntity(serverAddress + SecurityConstants
                .AAM_GET_COMPONENT_CERTIFICATE, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(certificationAuthorityHelper.getAAMCert(), response.getBody());
    }

    @Test
    public void getClientCertificateOverRESTInvalidArguments() throws NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException, KeyStoreException, IOException, OperatorCreationException, SecurityHandlerException {
        KeyPair pair = generateKeyPair();
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal(certificationAuthorityHelper.getAAMCertificate().getSubjectX500Principal().getName()), pair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(pair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(usernameWithAt,password,clientId,csr);
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_CLIENT_CERTIFICATE,
                certRequest, String.class);
        assertEquals("Credentials contain illegal sign",response.getBody());
    }

}