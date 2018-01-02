package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.ISecurityHandler;
import eu.h2020.symbiote.security.handler.SecurityHandler;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
@TestPropertySource("/platform.properties")
public class ComponentSecurityHandlerWithPlatformAAMTests extends AbstractAAMTestSuite {
    private final String KEY_STORE_PATH = "./src/test/resources/new.p12";
    private final String KEY_STORE_PASSWORD = "1234567";
    private String oldCoreAAMAddress;
    @Autowired
    private AAMServices aamServices;
    @LocalServerPort
    private int port;
    @Autowired
    private DummyCoreAAM dummyCoreAAM;

    @Before
    @Override
    public void setUp() throws
            Exception {
        super.setUp();
        dummyCoreAAM.port = port;
        oldCoreAAMAddress = (String) ReflectionTestUtils.getField(aamServices, "coreInterfaceAddress");
    }

    @After
    public void after() {
        //cleanup
        File file = new File(KEY_STORE_PATH);
        assertTrue(file.delete());
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", oldCoreAAMAddress);
    }

    @Test
    public void RegistrationHandlerIntegrationTest() throws
            SecurityHandlerException,
            InvalidArgumentsException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {
        // registration handler use case
        // hack: injecting the AAM running port
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");
        String rhKey = "rh";
        String regHandlerComponentId = rhKey + "@" + "platform-1";
        // generating the CSH
        IComponentSecurityHandler rhCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                regHandlerComponentId,
                serverAddress,
                AAMOwnerUsername,
                AAMOwnerPassword,
                Optional.empty()
        );

        // getting a CRM service response
        String regHandlerServiceResponse = rhCSH.generateServiceResponse();
        // making sure it won't issue certs multiple times
        String newRegHandlerServiceResponse = rhCSH.generateServiceResponse();

        // trying to validate the service response, yes we can use this SH as the operation is local
        assertTrue(rhCSH.isReceivedServiceResponseVerified(regHandlerServiceResponse, rhKey, "platform-1"));


        // trying to recreate the CSH with lost keystore
        File file = new File(KEY_STORE_PATH);
        assertTrue(file.delete());

        rhCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                regHandlerComponentId,
                serverAddress,
                AAMOwnerUsername,
                AAMOwnerPassword,
                Optional.empty()
        );

        // fetching the security response once more time
        newRegHandlerServiceResponse = rhCSH.generateServiceResponse();

        // trying to validate the service response, yes we can use this SH as the operation is local
        assertTrue(rhCSH.isReceivedServiceResponseVerified(newRegHandlerServiceResponse, rhKey, "platform-1"));
        assertFalse(rhCSH.isReceivedServiceResponseVerified(regHandlerServiceResponse, rhKey, "platform-1"));

        SecurityRequest rhSecurityRequest = rhCSH.generateSecurityRequestUsingLocalCredentials();
        assertFalse(rhSecurityRequest.getSecurityCredentials().isEmpty());

        // building dummy access policy
        Map<String, IAccessPolicy> testAP = new HashMap<>();
        String testPolicyId = "testPolicyId";
        SingleTokenAccessPolicySpecifier testPolicySpecifier =
                new SingleTokenAccessPolicySpecifier(rhKey, "platform-1");
        testAP.put(testPolicyId, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));
        // the policy should be there!
        assertTrue(rhCSH.getSatisfiedPoliciesIdentifiers(testAP, rhSecurityRequest).contains(testPolicyId));
        //change of the platform certificate in CoreAAM
        dummyCoreAAM.changePlatformCertificate();
        assertFalse(rhCSH.getSatisfiedPoliciesIdentifiers(testAP, rhSecurityRequest).contains(testPolicyId));
    }

    @Test
    public void loginBySecurityHandlerIntegrationTest() throws
            SecurityHandlerException,
            ValidationException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            IOException {

        addTestUserWithClientCertificateToRepository();
        // hack: injecting the AAM running port
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress + "/test/caam");
        ISecurityHandler securityHandler = new SecurityHandler(KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                serverAddress,
                username);
        AAM localAAM = securityHandler.getAvailableAAMs().get("platform-1");
        assertNotNull(localAAM);
        securityHandler.getCertificate(localAAM, username, password, clientId);
        Token token = securityHandler.login(localAAM);
        assertNotNull(token);
        assertEquals("platform-1", token.getClaims().getIssuer());
    }


}
