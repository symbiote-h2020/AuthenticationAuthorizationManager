package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import io.jsonwebtoken.Claims;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.File;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertFalse;

@TestPropertySource("/platform.properties")
public class ComponentSecurityHandlerWithPlatformAAMTests extends AbstractAAMTestSuite {
    private final String KEY_STORE_PATH = "./src/test/resources/new.p12";
    private final String KEY_STORE_PASSWORD = "1234567";
    private final String userId = "testuserId";
    @Autowired
    private AAMServices aamServices;
    @LocalServerPort
    private int port;
    @Autowired
    private DummyCoreAAM dummyCoreAAM;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        dummyCoreAAM.port = port;
    }

    @After
    public void after() {
        //cleanup
        File file = new File(KEY_STORE_PATH);
        assertTrue(file.delete());
    }

    @Test
    public void RegistrationHandlerIntegrationTest() throws SecurityHandlerException, InvalidArgumentsException, CertificateException, WrongCredentialsException {
        // hack: injecting the AAM running port
        String oldCoreAAMAddress = (String) ReflectionTestUtils.getField(aamServices, "coreAAMAddress");
        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress + "/test/caam");

        // registration handler use case
        String rhKey = "rh";
        String regHandlerComponentId = rhKey + "@" + "platform-1";
        // generating the CSH
        IComponentSecurityHandler rhCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                serverAddress + "/test/caam",
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                regHandlerComponentId,
                serverAddress,
                false,
                AAMOwnerUsername,
                AAMOwnerPassword
        );

        // getting a CRM service response
        String regHandlerServiceResponse = rhCSH.generateServiceResponse();

        // making sure it won't issue certs multiple times
        regHandlerServiceResponse = rhCSH.generateServiceResponse();

        // trying to validate the service response, yes we can use this SH as the operation is local
        assertTrue(rhCSH.isReceivedServiceResponseVerified(regHandlerServiceResponse, rhKey, "platform-1"));

        SecurityRequest rhSecurityRequest = rhCSH.generateSecurityRequestUsingLocalCredentials();
        assertFalse(rhSecurityRequest.getSecurityCredentials().isEmpty());

        // building dummy access policy
        Map<String, IAccessPolicy> testAP = new HashMap<>();
        String testPolicyId = "testPolicyId";
        Map<String, String> requiredClaims = new HashMap<>();
        requiredClaims.put(Claims.ISSUER, "platform-1");
        requiredClaims.put(Claims.SUBJECT, rhKey);
        SingleTokenAccessPolicySpecifier testPolicySpecifier =
                new SingleTokenAccessPolicySpecifier(
                        SingleTokenAccessPolicySpecifier.SingleTokenAccessPolicyType.SLHTIBAP,
                        requiredClaims);
        testAP.put(testPolicyId, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));
        // the policy should be there!
        assertTrue(rhCSH.getSatisfiedPoliciesIdentifiers(testAP, rhSecurityRequest).contains(testPolicyId));
        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", oldCoreAAMAddress);
    }


}
