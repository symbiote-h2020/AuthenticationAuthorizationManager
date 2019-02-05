package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.ClientSecurityHandlerFactory;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.handler.ISecurityHandler;
import eu.h2020.symbiote.security.services.AAMServices;
import org.junit.After;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.File;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

@TestPropertySource("/core_long_validity.properties")
public class ClientSecurityHandlerWithCoreAAMTests extends AbstractAAMTestSuite {
    private final String KEY_STORE_PATH = "./src/test/resources/keystores/new.p12";
    private final String KEY_STORE_PASSWORD = "1234567";
    @Autowired
    private AAMServices aamServices;

    @After
    public void after() {
        //cleanup
        File file = new File(KEY_STORE_PATH);
        assertTrue(file.delete());
    }

    @Test
    public void ClientIntegrationTest() throws
            SecurityHandlerException {
        // hack: injecting the AAM running port
        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress);

        ISecurityHandler securityHandler = ClientSecurityHandlerFactory.getSecurityHandler(serverAddress,
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD);

        // trying to get a certificate while passing bad certificate
        try {
            securityHandler.getCertificate(
                    null,
                    appUsername,
                    password,
                    "testClient");
        } catch (SecurityHandlerException e) {
            assertEquals("The AAM to request the client's certificate from is null has missing details address/certificate", e.getMessage());
        }

        // trying to get a certificate for unregistered user
        try {
            securityHandler.getCertificate(
                    securityHandler.getCoreAAMInstance(),
                    appUsername,
                    password,
                    "testClient");
        } catch (SecurityHandlerException e) {
            assertEquals(new NotExistingUserException().getErrorMessage(), e.getMessage());
        }

        // TODO add more tests!
    }
}
