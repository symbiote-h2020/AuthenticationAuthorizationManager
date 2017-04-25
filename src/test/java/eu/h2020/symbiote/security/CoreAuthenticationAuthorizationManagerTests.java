package eu.h2020.symbiote.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Test suite for Core AAM deployment scenarios.
 * TODO: 2-6,8,9,
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
    public void successfulPlatformRegistration() {
        // TODO define such tests
    }


    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void successfulApplicationRegistration() {
        // TODO define such tests
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void successfulApplicationUnregistration() {
        // TODO define such tests
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void externalRegistrationSuccess() {
        // TODO define such tests
    }

    /**
     * Feature: CAAM - 2 (App Registration)
     * Interface: CAAM - 3
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void externalUnregistrationSuccess() {
        // TODO define such tests
    }


    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 4
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void passwordUpdateSuccess() {
        // TODO define such tests
    }

    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 4
     * CommunicationType AMQP
     * User repeats the old password / doesn't change it
     */
    @Test
    @Ignore("Not yet implemented")
    public void passwordUpdateOldPasswordRepetition() {
        // TODO define such tests
    }

    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 4
     * CommunicationType AMQP
     * User leaves password argument empty
     */
    @Test
    @Ignore("Not yet implemented")
    public void passwordUpdateMissingPassword() {
        // TODO define such tests
    }


    /**
     * Feature: CAAM - 4 (Authentication)
     * Interface: CAAM - 4
     * CommunicationType AMQP
     * User gives wrong credentials (username/password mismatch)
     */
    @Test
    @Ignore("Not yet implemented")
    public void passwordUpdateWrongCredentials() {

    }

    /**
     * Feature: CAAM - 8 (Home to Core Tokens translation)
     * Interface: CAAM - 5
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void successfulAttributeProvision() {

    }

    /**
     * Feature: CAAM - 8 (Home to Core Tokens translation)
     * Interface: CAAM - 6
     * CommunicationType AMQP
     */
    @Test
    @Ignore("Not yet implemented")
    public void successfulAttributeMapping() {

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
    public void collectionListingSuccess() {

    }


}