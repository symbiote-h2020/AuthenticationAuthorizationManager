package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.SingleLocalHomeTokenIdentityBasedTokenAccessPolicy;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.helpers.PlatformAAMCertificateKeyStoreFactory;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.AAMServices;
import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;
import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.Assert.assertFalse;

@TestPropertySource("/long_validity_core.properties")
public class ComponentSecurityHandlerTests extends AbstractAAMTestSuite {
    private final String KEY_STORE_PATH = "./src/test/resources/new.p12";
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
    public void CRMIntegrationTest() throws SecurityHandlerException, InvalidArgumentsException {
        // hack: injecting the AAM running port
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress);
        String crmKey = "crm";
        String crmComponentId = crmKey + "@" + SecurityConstants.AAM_CORE_AAM_INSTANCE_ID;
        // generating the CSH
        IComponentSecurityHandler crmCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                serverAddress,
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                crmComponentId,
                serverAddress,
                false,
                AAMOwnerUsername,
                AAMOwnerPassword
        );

        // getting a CRM service response
        String crmServiceResponse = crmCSH.generateServiceResponse();

        // trying to validate the service response, yes we can use this SH as the operation is local
        assertTrue(crmCSH.isReceivedServiceResponseVerified(crmServiceResponse,
                crmCSH.getSecurityHandler().getComponentCertificate(crmComponentId)));

        SecurityRequest cmrSecurityRequest = crmCSH.generateSecurityRequestUsingCoreCredentials();
        assertFalse(cmrSecurityRequest.getSecurityCredentials().isEmpty());

        // building dummy access policy
        Map<String, IAccessPolicy> testAP = new HashMap<>();
        String testPolicyId = "testPolicyId";
        testAP.put(testPolicyId, new SingleLocalHomeTokenIdentityBasedTokenAccessPolicy(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID, AAMOwnerUsername, new HashMap<>()));

        // the policy should be there!
        assertTrue(crmCSH.getSatisfiedPoliciesIdentifiers(testAP, cmrSecurityRequest).contains(testPolicyId));
    }


    @Test
    @Ignore("WIP")
    public void RHIntegrationTest() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            ValidationException,
            KeyStoreException,
            InvalidArgumentsException,
            InvalidAlgorithmParameterException,
            NotExistingUserException,
            WrongCredentialsException,
            NoSuchProviderException {

        //platformOwner and platform  registration
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        Map<String, Platform> platforms = new HashMap<>();
        platforms.put(platformId, platform);
        platformOwner.setOwnedPlatforms(platforms);

        PlatformAAMCertificateKeyStoreFactory.getPlatformAAMKeystore(
                serverAddress, platformOwnerUsername, platformOwnerPassword, platformId, KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                "CORE_ALIAS", "KEY_TAG", PV_KEY_PASSWORD
        );
        //keyStore checking if proper Certificates exists
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (
                FileInputStream fIn = new FileInputStream(KEY_STORE_PATH)) {
            trustStore.load(fIn, KEY_STORE_PASSWORD.toCharArray());
            fIn.close();
            assertNotNull(trustStore.getCertificate("CORE_ALIAS"));
            assertNotNull(trustStore.getCertificate("KEY_TAG"));
        }
        //cleanup
        File file = new File(KEY_STORE_PATH);
        assertTrue(file.delete());
    }

}
