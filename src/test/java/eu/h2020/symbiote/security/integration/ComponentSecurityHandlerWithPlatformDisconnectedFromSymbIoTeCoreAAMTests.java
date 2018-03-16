package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.SecurityHandler;
import eu.h2020.symbiote.security.listeners.rest.controllers.AAMServicesController;
import eu.h2020.symbiote.security.services.AAMServices;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.doReturn;

@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
@TestPropertySource("/platform_no_ssl.properties")
public class ComponentSecurityHandlerWithPlatformDisconnectedFromSymbIoTeCoreAAMTests extends AbstractAAMTestSuite {
    private final String KEY_STORE_PATH = "./src/test/resources/keystores/new.p12";
    private final String KEY_STORE_PASSWORD = "1234567";

    @LocalServerPort
    private int port;

    @Autowired
    private AAMServices aamServices;

    @SpyBean
    private AAMServicesController spiedController;

    @Before
    @Override
    public void setUp() throws
            Exception {
        super.setUp();
        serverAddress = "http://127.0.0.1:" + port;
        aamClient = new AAMClient(serverAddress);
        ReflectionTestUtils.setField(aamServices, "localAAMUrl", serverAddress);
    }

    @After
    public void after() {
        //cleanup
        File file = new File(KEY_STORE_PATH);
        assertTrue(file.delete());
    }

    @Test
    public void ResourceAccessProxyIntegrationTest() throws
            SecurityHandlerException,
            InvalidArgumentsException {

        // registration handler use case
        String rapKey = "rap";
        String rapComponentId = rapKey + "@" + "platform-1";
        // generating the CSH
        IComponentSecurityHandler rhCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                rapComponentId,
                serverAddress,
                AAMOwnerUsername,
                AAMOwnerPassword
        );

        // getting a CRM service response
        String regHandlerServiceResponse = rhCSH.generateServiceResponse();
        // making sure it won't issue certs multiple times
        rhCSH.generateServiceResponse();

        // trying to validate the service response, yes we can use this SH as the operation is local
        assertTrue(rhCSH.isReceivedServiceResponseVerified(regHandlerServiceResponse, rapKey, "platform-1"));


        // trying to recreate the CSH with lost keystore
        File file = new File(KEY_STORE_PATH);
        assertTrue(file.delete());

        rhCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                rapComponentId,
                serverAddress,
                AAMOwnerUsername,
                AAMOwnerPassword
        );

        // fetching the security response once more time
        String newRegHandlerServiceResponse = rhCSH.generateServiceResponse();

        // trying to validate the service response, yes we can use this SH as the operation is local
        assertTrue(rhCSH.isReceivedServiceResponseVerified(newRegHandlerServiceResponse, rapKey, "platform-1"));
        assertFalse(rhCSH.isReceivedServiceResponseVerified(regHandlerServiceResponse, rapKey, "platform-1"));

        SecurityRequest rhSecurityRequest = rhCSH.generateSecurityRequestUsingLocalCredentials();
        assertFalse(rhSecurityRequest.getSecurityCredentials().isEmpty());

        // building dummy access policy
        Map<String, IAccessPolicy> testAP = new HashMap<>();
        String testPolicyId = "testPolicyId";
        SingleTokenAccessPolicySpecifier testPolicySpecifier =
                new SingleTokenAccessPolicySpecifier(rapKey, "platform-1");
        testAP.put(testPolicyId, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));
        // the policy should be there!
        assertTrue(rhCSH.getSatisfiedPoliciesIdentifiers(testAP, rhSecurityRequest).contains(testPolicyId));

        // testing old API fallback
        doReturn(new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR)).when(spiedController).getAAMsInternally();
        Map<String, AAM> availableAAMs = rhCSH.getSecurityHandler().getAvailableAAMs(serverAddress);
        assertFalse(availableAAMs.isEmpty());
    }

    @Test
    public void securityHandlerBuildsProperlyInIntranetPlatformIntegrationTest() throws
            SecurityHandlerException {

        SecurityHandler securityHandler = new SecurityHandler(KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                serverAddress,
                username);
        Map<String, AAM> availableAAMs = securityHandler.getAvailableAAMs(serverAddress);
        assertFalse(availableAAMs.isEmpty());
    }
}
