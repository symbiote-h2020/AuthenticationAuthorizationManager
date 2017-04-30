package eu.h2020.symbiote.security;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.exceptions.ExistingApplicationException;
import eu.h2020.symbiote.security.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.json.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for Core AAM deployment scenarios.
 */
public class CoreAuthenticationAuthorizationManagerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CoreAuthenticationAuthorizationManagerTests.class);

    private final String coreAppUsername = "testCoreAppUsername";
    private final String coreAppPassword = "testCoreAppPassword";
    private final String recoveryMail = "mail@abc.def";
    private final String federatedOAuthId = "federatedOAuthId";

    private RpcClient appRegistrationClient;


    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        appRegistrationClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                appRegistrationRequestQueue, 5000);
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void failurePlatformRegistrationUsernameExists() throws IOException, TimeoutException {
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                    platformRegistrationRequestQueue, 5000);
            byte[] response;
            /*
            response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new
            PlainCredentials("Username","Password"), "federatedID",
                "recoveryMail","platformIPAurl")).getBytes());
            PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
            PlatformRegistrationResponse.class);
            */
        } catch (Exception e) {
            /*
            assertEquals(new ExistingPlatformException().getErrorMessage(), e.getClass());
            */
        }

    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void failurePlatformRegistrationPlatformIdExists() throws IOException, TimeoutException {
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                    platformRegistrationRequestQueue, 5000);
            byte[] response;
            /*
            response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new
            PlainCredentials("Username","Password"),"federatedID",
                "preferredPlatformID","recoveryMail","platformIPAurl")).getBytes());
            PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
            PlatformRegistrationResponse.class);
            */
        } catch (Exception e) {
            /*
            assertEquals(new ExistingPlatformException().getErrorMessage(), e.getClass());
            */
        }

    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void successfulPlatformRegistrationWithPreferredPlatformId() throws IOException, TimeoutException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformRegistrationRequestQueue, 5000);
        byte[] response;

        response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new
                PlainCredentials("Username", "Password"), "federatedID",
                "preferredPlatformID", recoveryMail, "platformIPAurl")).getBytes());
        PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
                PlatformRegistrationResponse.class);

        log.info("Test Client received this key and certificate " + platformRegistrationResponse.toJson());

        assertNotEquals(platformRegistrationResponse.getPemCertificate(), null);
        assertNotEquals(platformRegistrationResponse.getPemPrivateKey(), null);
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void successfulPlatformRegistrationWithGeneratedPlatformId() throws IOException, TimeoutException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformRegistrationRequestQueue, 5000);
        byte[] response;

        response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new
                PlainCredentials("Username", "Password"), "federatedID",
                "recoveryMail", "platformIPAurl")).getBytes());
        PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
                PlatformRegistrationResponse.class);

        log.info("Test Client received this key and certificate " + platformRegistrationResponse.toJson());

        assertNotEquals(platformRegistrationResponse.getPemCertificate(), null);
        assertNotEquals(platformRegistrationResponse.getPemPrivateKey(), null);
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationFailureUnauthorized() throws IOException, TimeoutException {

        // verify that our app is not in repository
        assertNull(applicationRepository.findOne(coreAppUsername));

        // issue the same app registration over AMQP expecting with wrong AAMOwnerUsername
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                ApplicationRegistrationRequest(new
                PlainCredentials(AAMOwnerUsername + "wrongString", AAMOwnerPassword), new PlainCredentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail)).getBytes());

        // verify that our app was not registered in the repository
        assertNull(applicationRepository.findOne(coreAppUsername));

        // verify error response
        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("UNAUTHORIZED_APP_REGISTRATION", errorResponse.getErrorMessage());

        // issue the same app registration over AMQP expecting with wrong AAMOwnerUsername
        response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                ApplicationRegistrationRequest(new
                PlainCredentials(AAMOwnerUsername, AAMOwnerPassword + "wrongString"), new PlainCredentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail)).getBytes());

        // verify that our app was not registered in the repository
        assertNull(applicationRepository.findOne(coreAppUsername));

        // verify error response
        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("UNAUTHORIZED_APP_REGISTRATION", errorResponse.getErrorMessage());
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationFailureUsernameExists() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(applicationRepository.findOne(coreAppUsername));

        // issue app registration over AMQP
        appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                ApplicationRegistrationRequest(new
                PlainCredentials(AAMOwnerUsername, AAMOwnerPassword), new PlainCredentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail)).getBytes());


        // verify that app really is in repository
        assertNotNull(applicationRepository.findOne(coreAppUsername));

        // issue the same app registration over AMQP expecting refusal
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                ApplicationRegistrationRequest(new
                PlainCredentials(AAMOwnerUsername, AAMOwnerPassword), new PlainCredentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail)).getBytes());

        ErrorResponseContainer errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("APP_ALREADY_REGISTERED", errorResponse.getErrorMessage());
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationFailureMissingArguments() throws IOException, TimeoutException {
        // verify that our app is not in repository
        assertNull(applicationRepository.findOne(coreAppUsername));

        byte[] response;
        ErrorResponseContainer errorResponse;

        // issue app registration over AMQP with missing username
        response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                ApplicationRegistrationRequest(new
                PlainCredentials(AAMOwnerUsername, AAMOwnerPassword), new PlainCredentials(
                "", coreAppPassword), federatedOAuthId, recoveryMail)).getBytes());

        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("ERR_MISSING_ARGUMENTS", errorResponse.getErrorMessage());

        // issue app registration over AMQP with missing password
        response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                ApplicationRegistrationRequest(new
                PlainCredentials(AAMOwnerUsername, AAMOwnerPassword), new PlainCredentials(
                coreAppUsername, ""), federatedOAuthId, recoveryMail)).getBytes());

        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("ERR_MISSING_ARGUMENTS", errorResponse.getErrorMessage());

        // issue app registration over AMQP with missing federatedId
        response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                ApplicationRegistrationRequest(new
                PlainCredentials(AAMOwnerUsername, AAMOwnerPassword), new PlainCredentials(
                coreAppUsername, coreAppPassword), "", recoveryMail)).getBytes());

        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("ERR_MISSING_ARGUMENTS", errorResponse.getErrorMessage());

        // issue app registration over AMQP with missing recovery mail
        response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                ApplicationRegistrationRequest(new
                PlainCredentials(AAMOwnerUsername, AAMOwnerPassword), new PlainCredentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, "")).getBytes());

        errorResponse = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals("ERR_MISSING_ARGUMENTS", errorResponse.getErrorMessage());
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    public void applicationRegistrationSuccess() throws IOException, TimeoutException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException, MissingArgumentsException, KeyStoreException,
            InvalidAlgorithmParameterException, NoSuchProviderException, OperatorCreationException,
            WrongCredentialsException, ExistingApplicationException {

        // verify that our app is not in repository
        assertNull(applicationRepository.findOne(coreAppUsername));

        // issue app registration over AMQP
        byte[] response = appRegistrationClient.primitiveCall(mapper.writeValueAsString(new
                ApplicationRegistrationRequest(new
                PlainCredentials(AAMOwnerUsername, AAMOwnerPassword), new PlainCredentials(
                coreAppUsername, coreAppPassword), federatedOAuthId, recoveryMail)).getBytes());

        ApplicationRegistrationResponse appRegistrationResponse = mapper.readValue(response,
                ApplicationRegistrationResponse.class);

        log.info("Test Client received this key and certificate " + appRegistrationResponse.toJson());

        // verify that app really is in repository
        assertNotNull(applicationRepository.findOne(coreAppUsername));

        // verify that the server returns certificate & privateKey
        assertNotNull(appRegistrationResponse.getPemCertificate());
        assertNotNull(appRegistrationResponse.getPemPrivateKey());
    }
}