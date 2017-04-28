package eu.h2020.symbiote.security;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.commons.exceptions.ExistingApplicationException;
import eu.h2020.symbiote.security.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.json.ApplicationRegistrationResponse;
import eu.h2020.symbiote.security.commons.json.PlatformRegistrationResponse;
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
     *  TODO: PlatformRegistration failures with missing Username and missing Password
     */
    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void failurePlatformRegistrationUserNameExists() throws IOException, TimeoutException {
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
            byte[] response;
            /*
            response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new LoginRequest("username","password"),
                "recoveryMail","platformIPAurl")).getBytes());
            PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response, PlatformRegistrationResponse.class);
            */
        }
        catch(Exception e){
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
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
            byte[] response;
            /*
            response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new LoginRequest("username","password"),
                "preferredPlatformID","recoveryMail","platformIPAurl")).getBytes());
            PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response, PlatformRegistrationResponse.class);
            */
        }
        catch(Exception e){
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
    public void successfulPlatformRegistrationPreferredId() throws IOException, TimeoutException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response;
        /*
        response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new LoginRequest("username","password"),
            "preferredPlatformID","recoveryMail","platformIPAurl")).getBytes());
        PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response, PlatformRegistrationResponse.class);
        */
        PlatformRegistrationResponse platformRegistrationResponse = null;
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
    public void successfulPlatformRegistrationGeneratedId() throws IOException, TimeoutException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response;
        /*
        response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new LoginRequest("username","password"),
            "recoveryMail","platformIPAurl")).getBytes());
        PlatformRegistrationResponse platformRegistrationResponse = mapper.readValue(response, PlatformRegistrationResponse.class);
        */
        PlatformRegistrationResponse platformRegistrationResponse = null;
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
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
            byte[] response;
            /*
            response = client.primitiveCall(mapper.writeValueAsString(new ApplicationRegistrationRequest(new LoginRequest("username", "password"),
                "federatedId","recoveryMail").getBytes());
            ErrorResponseContainer noResponse = mapper.readValue(response, ErrorResponseContainer.class);
            */

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
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
            byte[] response;
            /*
            response= client.primitiveCall(mapper.writeValueAsString(new ApplicationRegistrationRequest(new LoginRequest(),"federatedId","recoveryMail")).getBytes());
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
    public void successfulApplicationRegistration() throws IOException, TimeoutException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, MissingArgumentsException, KeyStoreException, InvalidAlgorithmParameterException, NoSuchProviderException, OperatorCreationException, WrongCredentialsException, ExistingApplicationException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response;
        /*
        response= client.primitiveCall(mapper.writeValueAsString(new ApplicationRegistration(new LoginRequest("newUsername", "newPassword"),"federatedId","recoveryMail").getBytes());
        ApplicationRegistrationResponse appRegistrationResponse = mapper.readValue(response, ApplicationRegistrationResponse.class);
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
    @Ignore("Not yet implemented")
    public void successfulApplicationUnregistration() throws IOException, TimeoutException {
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
            byte[] response;
        /*
            response= client.primitiveCall(mapper.writeValueAsString(new LoginRequest("username", "password")).getBytes());
            ErrorResponseContainer noResponse = mapper.readValue(response, ErrorResponseContainer.class);
        */
        } catch (Exception e) {
            //TODO: NotExistingPlatformException?
            //assertEquals(NotExistingApplicationException.class, e.getClass());
        }
    }

    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 4
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
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
    @Ignore("Not yet implemented")
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
    @Ignore("Not yet implemented")
    public void passwordUpdateWrongCredentials() throws IOException, TimeoutException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
    }

    /**
     * Feature: CAAM - 8 (Home to Core Tokens translation)
     * Interface: CAAM - 5
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void issuedAttributesProvisioned() throws IOException, TimeoutException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response;
        /*
        response = client.primitiveCall(mapper.writeValueAsString(new LoginRequest("username", "password")).getBytes());
        ErrorResponseContainer noResponse = mapper.readValue(response, ErrorResponseContainer.class);
        */
        RpcClient client2 = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        byte[] response2;
        /*
        response2 =
         */



        /*
        1. zalogować się do AMMa jako AAM owner
        2. wysłać listę atrybutów
        3. zwróci sukces
        */
    }

    /**
     * Feature: CAAM - 8 (Home to Core Tokens translation)
     * Interface: CAAM - 6
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void federatedAttributeMappingListProvisioned() throws IOException, TimeoutException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
        /*
        1. payload na logowanie, albo token pozwalający na zarządzanie

         */
    }

    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 8
     * CommunicationType REST
     */
    @Test
    @Ignore("Not yet implemented")
    public void successfulPasswordReset() {

    }

    /**
     * Feature:
     * Interface: CAAM - 9
     * CommunicationType REST
     */
    @Test
    @Ignore("Not yet implemented")
    public void listWithMultipleAAMs() {

    }


}