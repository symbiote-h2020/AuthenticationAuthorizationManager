package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.ClientSecurityHandlerFactory;
import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.ISecurityHandler;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.AAMServices;
import io.jsonwebtoken.Claims;
import org.junit.After;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
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

@TestPropertySource("/long_validity_core.properties")
public class ComponentSecurityHandlerWithCoreAAMTests extends AbstractAAMTestSuite {
    private final String KEY_STORE_PATH = "./src/test/resources/new.p12";
    private final String KEY_STORE_PASSWORD = "1234567";
    private final String userId = "testuserId";
    @Autowired
    private AAMServices aamServices;

    @After
    public void after() {
        //cleanup
        File file = new File(KEY_STORE_PATH);
        assertTrue(file.delete());
    }

    @Test
    public void CoreResourceMonitorIntegrationTest() throws SecurityHandlerException, InvalidArgumentsException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException, WrongCredentialsException {
        // hack: injecting the AAM running port
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress);
        String crmKey = "crm";
        String crmComponentId = crmKey + "@" + SecurityConstants.CORE_AAM_INSTANCE_ID;
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
        assertTrue(crmCSH.isReceivedServiceResponseVerified(crmServiceResponse, crmKey, SecurityConstants.CORE_AAM_INSTANCE_ID));

        SecurityRequest crmSecurityRequest = crmCSH.generateSecurityRequestUsingCoreCredentials();
        assertFalse(crmSecurityRequest.getSecurityCredentials().isEmpty());

        // building test access policy
        Map<String, IAccessPolicy> testAP = new HashMap<>();
        String testPolicyId = "testPolicyId";

        ISecurityHandler clientSH = ClientSecurityHandlerFactory.getSecurityHandler(
                aamServices.getAvailableAAMs().get(SecurityConstants.CORE_AAM_INSTANCE_ID).getAamAddress(),
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                userId
        );
        SingleTokenAccessPolicySpecifier testPolicySpecifier =
                new SingleTokenAccessPolicySpecifier(crmKey, SecurityConstants.CORE_AAM_INSTANCE_ID,
                        clientSH);
        testAP.put(testPolicyId, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));
        // the policy should be there!
        assertTrue(crmCSH.getSatisfiedPoliciesIdentifiers(testAP, crmSecurityRequest).contains(testPolicyId));
    }


    @Test
    public void RegistrationHandlerIntegrationTest() throws SecurityHandlerException, InvalidArgumentsException {

        //platformOwner and platform  registration
        User platformOwner = savePlatformOwner();
        Platform platform = new Platform(platformId, null, null, platformOwner, new Certificate(), new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedPlatforms().add(platformId);
        userRepository.save(platformOwner);

        // hack: injecting the AAM running port
        ReflectionTestUtils.setField(aamServices, "coreInterfaceAddress", serverAddress);

        // registration handler use case
        String rhKey = "rh";
        String regHandlerComponentId = rhKey + "@" + platformId;
        // generating the CSH
        IComponentSecurityHandler rhCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                serverAddress,
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                regHandlerComponentId,
                serverAddress,
                false,
                platformOwnerUsername,
                platformOwnerPassword
        );

        // getting a CRM service response
        String regHandlerServiceResponse = rhCSH.generateServiceResponse();

        // making sure it won't issue certs multiple times
        regHandlerServiceResponse = rhCSH.generateServiceResponse();

        // trying to validate the service response, yes we can use this SH as the operation is local
        assertTrue(rhCSH.isReceivedServiceResponseVerified(regHandlerServiceResponse, rhKey, platformId));

        SecurityRequest rhSecurityRequest = rhCSH.generateSecurityRequestUsingCoreCredentials();
        assertFalse(rhSecurityRequest.getSecurityCredentials().isEmpty());

        // building dummy access policy
        Map<String, IAccessPolicy> testAP = new HashMap<>();
        String testPolicyId = "testPolicyId";
        Map<String, String> requiredClaims = new HashMap<>();
        requiredClaims.put(Claims.ISSUER, SecurityConstants.CORE_AAM_INSTANCE_ID);
        requiredClaims.put(Claims.SUBJECT, platformOwnerUsername);
        SingleTokenAccessPolicySpecifier testPolicySpecifier =
                new SingleTokenAccessPolicySpecifier(
                        SingleTokenAccessPolicySpecifier.SingleTokenAccessPolicyType.SLHTIBAP,
                        requiredClaims);
        testAP.put(testPolicyId, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));


        // the policy should be there!
        assertTrue(rhCSH.getSatisfiedPoliciesIdentifiers(testAP, rhSecurityRequest).contains(testPolicyId));
    }

}
