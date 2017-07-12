package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.exceptions.custom.NotExistingUserException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertEquals;

/**
 * Temporary tests suite for already defined but not yet implemented Release 3 functionality
 *
 * @author Mikołaj Dobski (PSNC)
 */
@Ignore("Release 3 tests")
@TestPropertySource("/core.properties")
public class Release3FunctionalTests extends AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(Release3FunctionalTests.class);


    /**
     * Feature: common but defined in CAAM - 5 (Token with AAM relevant attribute provisioning and issuing)
     * Interface: CAAM - 5
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not R2 crucial, at R2 we will issue attributes from properties")
    public void common_provisionedAttributesIssuedToRegisteredApplication() throws IOException, TimeoutException {
        /*
            // R2
        1. log in to AAM as an AAM owner
        2. send the attributes list
        3. receive a success status
        4. log in as an user and check if the token does contain sent attributes
        */
    }

    /**
     * Feature: common but defined in CAAM - 8 (Home to Core/Foreign Tokens translation with federation agreed
     * provisioned attributes mapping)
     * Interface: CAAM - 6
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not R2")
    public void common_federatedAttributesIssuedUsingProvisionedAttributesMappingList() throws IOException, TimeoutException {
        /*
        // R2
        1. log in to AAM as an AAM owner
        2. send an attribute mapping list
        3. receive a success status
        4. request foreign tokens which should be based on given tokens
        */
    }

    /**
     * Feature: CAAM - 3 (Platform Registration)
     * Interface: CAAM - 2
     * CommunicationType AMQP
     */
    @Test
    @Ignore("OauthId is not R2! Not yet implemented")
    public void caam_failurePlatformRegistrationFederatedIdExists() throws IOException, TimeoutException {
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                    platformRegistrationRequestQueue, 5000);
            byte[] response;
            /*
            response = client.primitiveCall(mapper.writeValueAsString(new PlatformRegistrationRequest(new
            Credentials("username","password"), "federatedID"
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
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not required for R2, Not yet implemented")
    public void caam_successfulApplicationUnregistration() throws IOException, TimeoutException {
        try {
            RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue,
                    5000);
            byte[] response;
        /*
            response= client.primitiveCall(mapper.writeValueAsString(new Credentials("username", "password"))
            .getBytes());
            ErrorResponseContainer noResponse = mapper.readValue(response, ErrorResponseContainer.class);
        */
        } catch (Exception e) {
            assertEquals(NotExistingUserException.class, e.getClass());
        }
    }

    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 4
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not required for R2, Not yet implemented")
    public void caam_passwordUpdateSuccess() throws IOException, TimeoutException {
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
    public void caam_passwordUpdateMissingPassword() throws IOException, TimeoutException {
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
    public void caam_passwordUpdateWrongCredentials() throws IOException, TimeoutException {
        RpcClient client = new RpcClient(rabbitManager.getConnection().createChannel(), "", loginRequestQueue, 5000);
    }


    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 8
     * CommunicationType REST
     */
    @Test
    @Ignore("Not required for R2, Not yet implemented")
    public void caam_successfulPasswordReset() {

    }

}
