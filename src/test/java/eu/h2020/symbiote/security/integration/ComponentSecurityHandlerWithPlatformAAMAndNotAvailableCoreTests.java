package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.SecurityHandler;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.AAMServices;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.support.AopUtils;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.mock.mockito.SpyBean;
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

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.doThrow;

@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestPropertySource("/platform_no_ssl.properties")
public class ComponentSecurityHandlerWithPlatformAAMAndNotAvailableCoreTests extends AbstractAAMTestSuite {
    private final String KEY_STORE_PATH = "./src/test/resources/new.p12";
    private final String KEY_STORE_PASSWORD = "1234567";

    @LocalServerPort
    private int port;
    @SpyBean
    private AAMServices spied;

    public static Object unwrapProxy(Object bean) throws Exception {
        /*
         * If the given object is a proxy, set the return value as the object
         * being proxied, otherwise return the given object.
         */
        if (AopUtils.isAopProxy(bean) && bean instanceof Advised) {
            Advised advised = (Advised) bean;
            bean = advised.getTargetSource().getTarget();
        }
        return bean;
    }

    @Before
    @Override
    public void setUp() throws
            Exception {
        super.setUp();
        serverAddress = "http://localhost:" + port;
        aamClient = new AAMClient(serverAddress);
        userKeyPair = CryptoHelper.createKeyPair();

        // cleanup db
        userRepository.deleteAll();
        revokedKeysRepository.deleteAll();
        revokedTokensRepository.deleteAll();
        platformRepository.deleteAll();
        componentCertificatesRepository.deleteAll();
        localUsersAttributesRepository.deleteAll();

        // mock initialization
        AAMServices validationService = (AAMServices) unwrapProxy(spied);
        doThrow(new AAMException("Not working - Core is not available")).when(validationService).getAvailableAAMs();
        ReflectionTestUtils.setField(spied, "platformInterworkingInterfaceUrl", serverAddress);
    }

    @After
    public void after() {
        //cleanup
        File file = new File(KEY_STORE_PATH);
        assertTrue(file.delete());
    }

    @Test
    public void RegistrationHandlerIntegrationTest() throws
            SecurityHandlerException,
            InvalidArgumentsException {

        // registration handler use case
        String rhKey = "rh";
        String regHandlerComponentId = rhKey + "@" + "platform-1";
        // generating the CSH
        IComponentSecurityHandler rhCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                serverAddress,
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                regHandlerComponentId,
                serverAddress,
                true,
                AAMOwnerUsername,
                AAMOwnerPassword
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
                serverAddress,
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                regHandlerComponentId,
                serverAddress,
                true,
                AAMOwnerUsername,
                AAMOwnerPassword
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
    }

    @Test(expected = SecurityHandlerException.class)
    public void loginBySecurityHandlerIntegrationTest() throws
            SecurityHandlerException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            IOException {

        addTestUserWithClientCertificateToRepository();
        new SecurityHandler(KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                serverAddress,
                username);
    }


}
