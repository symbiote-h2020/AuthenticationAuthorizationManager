package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AuthenticationAuthorizationManagerTests;
import eu.h2020.symbiote.security.InternalSecurityHandler;
import eu.h2020.symbiote.security.SecurityHandler;
import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.exceptions.aam.ExistingUserException;
import eu.h2020.symbiote.security.exceptions.aam.MalformedJWTException;
import eu.h2020.symbiote.security.exceptions.aam.NotExistingUserException;
import eu.h2020.symbiote.security.exceptions.aam.TokenValidationException;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.payloads.UserDetails;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import eu.h2020.symbiote.security.payloads.UserRegistrationResponse;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.List;
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

    @Value("${rabbit.host}")
    protected String rabbitHost;
    @Value("${rabbit.username}")
    protected String rabbitUsername;
    @Value("${rabbit.password}")
    protected String rabbitPassword;
    private InternalSecurityHandler internalSecurityHandler;
    private SecurityHandler securityHandler;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        internalSecurityHandler =
                new InternalSecurityHandler(serverAddress, rabbitHost, rabbitUsername, rabbitPassword);
        securityHandler = new SecurityHandler(serverAddress);
    }

    /**
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     */
    @Test
    public void applicationLoginOverAMQPWrongCredentialsFailure()
            throws IOException, TimeoutException, SecurityHandlerException {
        Token token = null;
        try {
            token = internalSecurityHandler.requestFederatedCoreToken(wrongusername, password);
        } catch (SecurityHandlerException e) {
            assertEquals(e.getMessage(), AAMConstants.ERR_WRONG_CREDENTIALS);
        }
        assertNull(token);
        try {
            token = internalSecurityHandler.requestFederatedCoreToken(username, wrongpassword);
        } catch (SecurityHandlerException e) {
            assertEquals(e.getMessage(), AAMConstants.ERR_WRONG_CREDENTIALS);
        }
        assertNull(token);

        try {
            token = internalSecurityHandler.requestFederatedCoreToken(wrongusername, wrongpassword);
        } catch (SecurityHandlerException e) {
            assertEquals(e.getMessage(), AAMConstants.ERR_WRONG_CREDENTIALS);
        }
        assertNull(token);
    }

    /**
     * Feature: 3 (Authentication of components/ and applications registered in a platform)
     * Interface: PAAM - 1, CAAM (for Administration)
     * CommunicationType AMQP
     */
    @Test
    public void applicationLoginOverAMQPMissingArgumentsFailure() {
        Token token = null;
        try {
            token = internalSecurityHandler.requestFederatedCoreToken("", "");
        } catch (SecurityHandlerException e) {
            assertEquals(e.getMessage(), AAMConstants.ERR_MISSING_ARGUMENTS);
        }
        assertNull(token);
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
            TokenValidationException, SecurityHandlerException {

        Token token = internalSecurityHandler.requestHomeToken(username, password);

        ValidationStatus status = internalSecurityHandler.verifyHomeToken(token);
        log.info("Test Client received this TokenValidationStatus: " + status.toString());

        assertEquals(ValidationStatus.VALID, status);
    }


    @Test
    public void userLoginOverRESTWrongCredentialsFailure() {
        Token token = null;
        try {
            token = securityHandler.requestCoreToken(wrongusername, password);
        } catch (SecurityException e) {
            assertEquals(AAMConstants.ERR_WRONG_CREDENTIALS, e.getMessage());
        }
        assertNull(token);
        try {
            token = securityHandler.requestCoreToken(username, wrongpassword);
        } catch (SecurityException e) {
            assertEquals(AAMConstants.ERR_WRONG_CREDENTIALS, e.getMessage());
        }
        assertNull(token);

        try {
            token = securityHandler.requestCoreToken(wrongusername, wrongpassword);
        } catch (SecurityException e) {
            assertEquals(AAMConstants.ERR_WRONG_CREDENTIALS, e.getMessage());
        }
        assertNull(token);
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void applicationLoginOverRESTSuccessAndIssuesCoreTokenWithoutPOAttributes() {

        Token token = securityHandler.requestCoreToken(username, password);
        assertNotNull(token.getToken());

        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
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
    public void foreignTokenRequestOverRESTSuccessWithoutCoreToken() throws SecurityHandlerException {
        List<AAM> aams = securityHandler.getAvailableAAMs();
        securityHandler.requestCoreToken(username, password);
        Map<String, Token> foreignTokens = securityHandler.requestForeignTokens(aams);
        assertNotNull(foreignTokens);
        assertFalse(foreignTokens.containsKey(AAMConstants.AAM_CORE_AAM_INSTANCE_ID));
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
        Token token = securityHandler.requestCoreToken(username, password);
        assertNotNull(token.getToken());
        ValidationStatus status = securityHandler.verifyCoreToken(token);
        assertEquals(ValidationStatus.VALID, status);
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
        Token token = securityHandler.requestCoreToken(username, password);
        assertNotNull(token.getToken());
        //Introduce latency so that JWT expires
        try {
            Thread.sleep(tokenValidityPeriod + 1000);
        } catch (InterruptedException e) {
            log.error(e);
        }
        ValidationStatus status = securityHandler.verifyCoreToken(token);
        assertEquals(ValidationStatus.EXPIRED, status);
    }

    /**
     * Feature: User Repository
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    @Ignore // SH does not support registration procedure
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
    @Ignore // SH does not support registration procedure
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
     * Features: CAAM - 12 (AAM as a CA)
     * Interfaces: CAAM - 15;
     * CommunicationType REST
     */
    @Test
    @Ignore("moved to unit tests")
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