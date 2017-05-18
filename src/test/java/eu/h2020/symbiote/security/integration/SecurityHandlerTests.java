package eu.h2020.symbiote.security.integration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AuthenticationAuthorizationManagerTests;
import eu.h2020.symbiote.security.SecurityHandler;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.AAMException;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.exceptions.aam.MalformedJWTException;
import eu.h2020.symbiote.security.functional.CoreAuthenticationAuthorizationManagerTests;
import eu.h2020.symbiote.security.payloads.*;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;

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
 * Created by Maks on 2017-05-16.
 */
@TestPropertySource("/core.properties")
public class SecurityHandlerTests extends AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CoreAuthenticationAuthorizationManagerTests.class);
    @Rule
    public final ExpectedException exception = ExpectedException.none();
    private final String coreAppUsername = "testCoreAppUsername";
    private final String coreAppPassword = "testCoreAppPassword";
    private final String recoveryMail = "null@dev.null";
    private final String federatedOAuthId = "federatedOAuthId";
    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    private final String platformInterworkingInterfaceAddress =
            "https://platform1.eu:8101/someFancyHiddenPath/andHiddenAgain";
    private final String platformOwnerUsername = "testPlatformOwnerUsername";
    private final String platformOwnerPassword = "testPlatormOwnerPassword";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    //private UserRegistrationRequest appUserRegistrationRequest;
    private RpcClient appRegistrationClient;
    //private UserDetails appUserDetails;
    private RpcClient platformRegistrationOverAMQPClient;
    //private UserDetails platformOwnerUserDetails;
    private PlatformRegistrationRequest platformRegistrationOverAMQPRequest;
    @Autowired
    private PlatformRepository platformRepository;

    /**
     * Features: CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void platformOwnerLoginOverRESTSuccessAndIssuesRelevantTokenTypeWithPOAttributesUsingSecurityHandler() throws IOException,
            TimeoutException, MalformedJWTException, JSONException, CertificateException {
        // verify that our platform and platformOwner are not in repositories
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertFalse(userRepository.exists(platformOwnerUsername));

        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());


        /*
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(platformOwnerUsername, platformOwnerPassword), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        //verify that JWT was issued for user
        assertNotNull(headers.getFirst(AAMConstants.TOKEN_HEADER_NAME));

        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(AAMConstants.TOKEN_HEADER_NAME));
        */

        SecurityHandler securityHandler = new SecurityHandler(serverAddress+ AAMConstants.AAM_LOGIN);
        Token token = securityHandler.requestCoreToken(platformOwnerUsername,platformOwnerPassword);
        assertNotNull(token.getToken());


        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());

        //verify that JWT is of type Core as was released by a CoreAAM
        assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

        // verify that the token contains the platform owner public key
        byte[] applicationPublicKeyInRepository = userRepository.findOne
                (platformOwnerUsername).getCertificate().getX509().getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.decodeBase64(claimsFromToken.getSpk());
        assertArrayEquals(applicationPublicKeyInRepository, publicKeyFromToken);

        // verify that this JWT contains attributes relevant for platform owner
        Map<String, String> attributes = claimsFromToken.getAtt();
        // PO role
        assertEquals(UserRole.PLATFORM_OWNER.toString(), attributes.get(CoreAttributes.ROLE.toString()));
        // owned platform identifier
        assertEquals(preferredPlatformId, attributes.get(CoreAttributes.OWNED_PLATFORM.toString()));
    }




    /**
     * Features: Core AAM  providing list of available security entry points
     * CommunicationType REST
     */
    @Test
    public void getAvailableAAMsOverRESTWithNoRegisteredPlatformsUsingSecurityHandler() throws NoSuchAlgorithmException,
            CertificateException, NoSuchProviderException, KeyStoreException, IOException, SecurityHandlerException {

        /*
        ResponseEntity<List<AAM>> response = restTemplate.exchange(serverAddress + AAMConstants
                .AAM_GET_AVAILABLE_AAMS, HttpMethod.GET, null, new ParameterizedTypeReference<List<AAM>>() {
        });
        assertEquals(HttpStatus.OK, response.getStatusCode());
        // verify the body

        List<AAM> aams = response.getBody();
        */

        SecurityHandler securityHandler = new SecurityHandler(serverAddress);
        List<AAM> aams = securityHandler.getAvailableAAMs();

        // there should be only core AAM in the list
        assertEquals(1, aams.size());

        // verifying the contents
        AAM aam = aams.get(0);
        // this expected PlatformAAM is due to the value stored in the issued certificate in the test keystore
        assertEquals(AAMConstants.AAM_CORE_AAM_INSTANCE_ID, aam.getAamInstanceId());
        assertEquals(coreInterfaceAddress, aam.getAamAddress());
        // maybe we could externalize it to spring config
        assertEquals(AAMConstants.AAM_CORE_AAM_FRIENDLY_NAME, aam.getAamInstanceFriendlyName());
        assertEquals(registrationManager.getAAMCert(), aam.getCertificate().getCertificateString());
    }


    /**
     * Features: Core AAM  providing list of available security entrypoints
     * CommunicationType REST
     */
    @Test
    public void getAvailableAAMsOverRESTWithRegisteredPlatformUsingSecurityHandler() throws AAMException, IOException, TimeoutException, SecurityHandlerException {
        // issue platform registration over AMQP
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        /*
        // get the list
        ResponseEntity<List<AAM>> response = restTemplate.exchange(serverAddress + AAMConstants
                .AAM_GET_AVAILABLE_AAMS, HttpMethod.GET, null, new ParameterizedTypeReference<List<AAM>>() {
        });
        assertEquals(HttpStatus.OK, response.getStatusCode());

        // verify the body
        List<AAM> aams = response.getBody();
        */
        SecurityHandler securityHandler = new SecurityHandler(serverAddress);

        List<AAM> aams = securityHandler.getAvailableAAMs();

        // there should be Core AAM and the registered platform
        assertEquals(2, aams.size());

        // verifying the contents
        // first should be served the core AAM
        AAM coreAAM = aams.get(0);
        // this expected PlatformAAM is due to the value stored in the issued certificate in the test keystore
        assertEquals(AAMConstants.AAM_CORE_AAM_INSTANCE_ID, coreAAM.getAamInstanceId());
        assertEquals(coreInterfaceAddress, coreAAM.getAamAddress());
        assertEquals(AAMConstants.AAM_CORE_AAM_FRIENDLY_NAME, coreAAM.getAamInstanceFriendlyName());

        // then comes the registered platform
        AAM platformAAM = aams.get(1);
        assertEquals(preferredPlatformId, platformAAM.getAamInstanceId());
        assertEquals(platformInterworkingInterfaceAddress + platformAAMSuffixAtInterWorkingInterface, platformAAM
                .getAamAddress());
        assertEquals(platformInstanceFriendlyName, platformAAM.getAamInstanceFriendlyName());
        // TODO we don't know the cert... until R3 when we will know it
        assertEquals("", platformAAM.getCertificate().getCertificateString());

    }


    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void userLoginOverRESTWrongUsernameFailureUsingSecurityHandler() {
        SecurityHandler securityHandler = new SecurityHandler(serverAddress+ AAMConstants.AAM_LOGIN);
        securityHandler.requestCoreToken(wrongusername, password);
        exception.expect(SecurityException.class);
        //exception.expectMessage("It was not possible to validate you with the give credentials. Please " +
        //       "check them");
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void userLoginOverRESTWrongPasswordFailureUsingSecurityHandler() {
        SecurityHandler securityHandler = new SecurityHandler(serverAddress+ AAMConstants.AAM_LOGIN);
        Token token = securityHandler.requestCoreToken(username,wrongpassword);
        exception.expect(SecurityException.class);
        //exception.expectMessage("It was not possible to validate you with the give credentials. Please " +
        //        "check them");
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void applicationLoginOverRESTSuccessAndIssuesCoreTokenWithoutPOAttributesUsingSecurityHandler() {

        /*ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(headers.getFirst(AAMConstants.TOKEN_HEADER_NAME));
        */
        SecurityHandler securityHandler = new SecurityHandler(serverAddress+ AAMConstants.AAM_LOGIN);
        Token token = securityHandler.requestCoreToken(username,wrongpassword);
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
     * Features: PAAM - 5,6,8 (synchronous token validation, asynchronous token validation, management of token
     * revocation),
     * CAAM - 5 (Revoking tokens based on expiration date or illegal access)
     * Interfaces: PAAM - 4, CAAM - 10;
     * CommunicationType REST
     */
    @Test
    @Ignore
    public void checkTokenRevocationOverRESTValidUsingSecurityHandler() {

        SecurityHandler securityHandler = new SecurityHandler(serverAddress + AAMConstants.AAM_LOGIN);


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
    @Ignore
    public void checkTokenRevocationOverRESTExpiredUsingSecurityHandler() {

        SecurityHandler securityHandler = new SecurityHandler(serverAddress + AAMConstants.AAM_LOGIN);


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
     * Features: CAAM - 12 (AAM as a CA)
     * Interfaces: CAAM - 15;
     * CommunicationType REST
     */
    @Test
    @Ignore
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

    /**
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */
    @Test
    @Ignore
    public void foreignTokenRequestOverRESTSuccessUsingSecurityHandler() {

        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + AAMConstants.AAM_LOGIN,
                new Credentials(username, password), String.class);
        HttpHeaders loginHeaders = response.getHeaders();


        MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
        headers.add(AAMConstants.TOKEN_HEADER_NAME, loginHeaders.getFirst(AAMConstants.TOKEN_HEADER_NAME));

        HttpEntity<String> request = new HttpEntity<String>(null, headers);

        ResponseEntity<String> responseToken = restTemplate.postForEntity(serverAddress + AAMConstants
                        .AAM_REQUEST_FOREIGN_TOKEN, request, String.class);
        HttpHeaders rspHeaders = responseToken.getHeaders();

        assertEquals(HttpStatus.OK, responseToken.getStatusCode());
        assertNotNull(rspHeaders.getFirst(AAMConstants.TOKEN_HEADER_NAME));
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
    @Ignore
    public void applicationRegistrationOverRESTSuccessUsingSecurityHandler() throws JsonProcessingException {
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
    @Ignore
    public void applicationUnegistrationOverRESTSuccessUsingSecurityHandler() throws JsonProcessingException {
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
