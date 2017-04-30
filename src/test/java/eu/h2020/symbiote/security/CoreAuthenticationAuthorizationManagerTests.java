package eu.h2020.symbiote.security;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.exceptions.ExistingApplicationException;
import eu.h2020.symbiote.security.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.json.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertNotEquals;

/**
 * Test suite for Core AAM deployment scenarios.
 */
public class CoreAuthenticationAuthorizationManagerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CoreAuthenticationAuthorizationManagerTests.class);

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
            PlainCredentials("username","password"), "federatedID",
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
            PlainCredentials("username","password"),"federatedID",
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
                PlainCredentials("username", "password"), "federatedID",
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
                PlainCredentials("username", "password"), "federatedID",
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
                    PlainCredentials(AAMOwnerUsername, AAMOwnerPassword), new
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


}