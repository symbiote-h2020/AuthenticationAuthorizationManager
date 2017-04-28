package eu.h2020.symbiote.security;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.exceptions.ExistingApplicationException;
import eu.h2020.symbiote.security.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.NotExistingApplicationException;
import eu.h2020.symbiote.security.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.json.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * Test suite for Core AAM deployment scenarios.
 */
public class CoreAuthenticationAuthorizationManagerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CoreAuthenticationAuthorizationManagerTests.class);

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    @Ignore("JWT ttyp Not yet implemented")
    public void externalLoginIssuesCoreToken() {
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + loginUri,
                new PlainCredentials(username, password), String.class);
        HttpHeaders headers = response.getHeaders();
        assertEquals(response.getStatusCode(), HttpStatus.OK);
        assertNotEquals(headers.getFirst(tokenHeaderName), null);
        // TODO: check if JWT ttyp field is set to CORE
    }


    /**
     *  TODO: PlatformRegistration failures with missing Username and missing Password
     */

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("OauthId is not R2! Not yet implemented")
    public void failurePlatformRegistrationFederatedIdExists() throws IOException, TimeoutException {
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                    platformRegistrationRequestQueue, 5000);
            byte[] response;
            /*
            response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new
            PlainCredentials("username","password"),
                "recoveryMail","platformIPAurl")).getBytes());
            PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
            PlatformRegistrationResponse.class);
            */
        } catch (Exception e) {
            /*TODO:ExistingPlatformException?
            assertEquals(new ExistingPlatformIDException().getErrorMessage(), e.getClass());
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
    public void failurePlatformRegistrationUsernameExists() throws IOException, TimeoutException {
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                    platformRegistrationRequestQueue, 5000);
            byte[] response;
            /*
            response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new
            PlainCredentials("username","password"),
                "recoveryMail","platformIPAurl")).getBytes());
            PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
            PlatformRegistrationResponse.class);
            */
        } catch (Exception e) {
            /*TODO:ExistingPlatformException?
            assertEquals(new ExistingPlatformIDException().getErrorMessage(), e.getClass());
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
            PlainCredentials("username","password"),
                "preferredPlatformID","recoveryMail","platformIPAurl")).getBytes());
            PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response,
            PlatformRegistrationResponse.class);
            */
        } catch (Exception e) {
            /*TODO: ExistingPlatformIDException?
            assertEquals(new ExistingPlatformIDException().getErrorMessage(), e.getClass());
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
                PlainCredentials("username", "password"),
                "preferredPlatformID", "recoveryMail", "platformIPAurl")).getBytes());
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
                PlainCredentials("username", "password"),
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
    @Ignore("Not yet implemented")
    public void failureApplicationRegistrationUsernameExists() throws IOException, TimeoutException {
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                    appRegistrationRequestQueue, 5000);
            byte[] response;

            response = client.primitiveCall(mapper.writeValueAsString(new ApplicationRegistrationRequest(new
                    PlainCredentials("username", "password"),
                    "federatedId", "recoveryMail")).getBytes());
            ErrorResponseContainer noResponse = mapper.readValue(response, ErrorResponseContainer.class);


        } catch (Exception e) {
            //assertEquals(new ExistingApplicationException().getErrorMessage(), e.getClass());
        }
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void failureApplicationRegistrationMissingArguments() throws IOException, TimeoutException {
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                    appRegistrationRequestQueue, 5000);
            byte[] response;
            /*
            response= client.primitiveCall(mapper.writeValueAsString(new ApplicationRegistrationRequest(new
            PlainCredentials(),"federatedId","recoveryMail")).getBytes());
            ErrorResponseContainer noResponse = mapper.readValue(response, ErrorResponseContainer.class);
            */
        } catch (Exception e) {
            //assertEquals(new MissingArgumentsException().getErrorMessage(), e.getClass());
        }
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void successfulApplicationRegistration() throws IOException, TimeoutException, CertificateException,
            NoSuchAlgorithmException, UnrecoverableKeyException, MissingArgumentsException, KeyStoreException,
            InvalidAlgorithmParameterException, NoSuchProviderException, OperatorCreationException,
            WrongCredentialsException, ExistingApplicationException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                appRegistrationRequestQueue, 5000);
        byte[] response;
        /*
        response= client.primitiveCall(mapper.writeValueAsString(new ApplicationRegistration(new PlainCredentials
        ("newUsername", "newPassword"),"federatedId","recoveryMail").getBytes());
        ApplicationRegistrationResponse appRegistrationResponse = mapper.readValue(response,
        ApplicationRegistrationResponse.class);
        */
        ApplicationRegistrationResponse registrationResponse = null;
        log.info("Test Client received this key and certificate " + registrationResponse.toJson());

        assertNotEquals(registrationResponse.getPemCertificate(), null);
        assertNotEquals(registrationResponse.getPemPrivateKey(), null);
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not required for R2, Not yet implemented")
    public void successfulApplicationUnregistration() throws IOException, TimeoutException {
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue,
                    5000);
            byte[] response;
        /*
            response= client.primitiveCall(mapper.writeValueAsString(new PlainCredentials("username", "password"))
            .getBytes());
            ErrorResponseContainer noResponse = mapper.readValue(response, ErrorResponseContainer.class);
        */
        } catch (Exception e) {
            assertEquals(NotExistingApplicationException.class, e.getClass());
        }
    }

    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 4
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not required for R2, Not yet implemented")
    public void passwordUpdateSuccess() throws IOException, TimeoutException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
    }

    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 4
     * CommunicationType AMQP
     * User leaves password argument empty
     */
    @Test
    @Ignore("Not required for R2, Not yet implemented")
    public void passwordUpdateMissingPassword() throws IOException, TimeoutException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
    }


    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 4
     * CommunicationType AMQP
     * User gives wrong credentials (username/password mismatch)
     */
    @Test
    @Ignore("Not required for R2, Not yet implemented")
    public void passwordUpdateWrongCredentials() throws IOException, TimeoutException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
    }


    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 8
     * CommunicationType REST
     */
    @Test
    @Ignore("Not required for R2, Not yet implemented")
    public void successfulPasswordReset() {

    }


}