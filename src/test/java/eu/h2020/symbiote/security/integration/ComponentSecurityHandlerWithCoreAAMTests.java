package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.junit.After;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

@TestPropertySource("/core_long_validity.properties")
public class ComponentSecurityHandlerWithCoreAAMTests extends AbstractAAMTestSuite {
    private final String KEY_STORE_PATH = "./src/test/resources/keystores/new.p12";
    private final String KEY_STORE_PASSWORD = "1234567";
    @Autowired
    private AAMServices aamServices;
    @SpyBean
    private CertificationAuthorityHelper certificationAuthorityHelper;

    @After
    public void after() {
        //cleanup
        File file = new File(KEY_STORE_PATH);
        assertTrue(file.delete());
        when(certificationAuthorityHelper.getAAMCertificate()).thenCallRealMethod();
    }

    @Test
    public void coreResourceMonitorIntegrationTest() throws
            SecurityHandlerException,
            InvalidArgumentsException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {
        // hack: injecting the AAM running port
        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress);
        String crmKey = "crm";
        String crmComponentId = crmKey + "@" + SecurityConstants.CORE_AAM_INSTANCE_ID;
        // generating the CSH
        IComponentSecurityHandler crmCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                crmComponentId,
                serverAddress,
                AAMOwnerUsername,
                AAMOwnerPassword
        );

        // getting a CRM service response
        String crmServiceResponse = crmCSH.generateServiceResponse();

        // trying to validate the service response, yes we can use this SH as the operation is local
        assertTrue(crmCSH.isReceivedServiceResponseVerified(crmServiceResponse, crmKey, SecurityConstants.CORE_AAM_INSTANCE_ID));

        SecurityRequest crmSecurityRequest = crmCSH.generateSecurityRequestUsingLocalCredentials();
        assertFalse(crmSecurityRequest.getSecurityCredentials().isEmpty());

        // building test access policy
        Map<String, IAccessPolicy> testAP = new HashMap<>();
        String testPolicyId = "testPolicyId";

        SingleTokenAccessPolicySpecifier testPolicySpecifier =
                new SingleTokenAccessPolicySpecifier(crmKey, SecurityConstants.CORE_AAM_INSTANCE_ID);
        testAP.put(testPolicyId, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));
        // the policy should be there!
        assertTrue(crmCSH.getSatisfiedPoliciesIdentifiers(testAP, crmSecurityRequest).contains(testPolicyId));

        //saving credentials to delete
        BoundCredentials temp = crmCSH.getSecurityHandler().getAcquiredCredentials().get(SecurityConstants.CORE_AAM_INSTANCE_ID);
        // changing the component SPK by cleaning the current one
        crmCSH.getSecurityHandler().getAcquiredCredentials().remove(SecurityConstants.CORE_AAM_INSTANCE_ID);
        crmCSH.generateServiceResponse();
        // attempting authenticate using invalid token
        assertFalse(crmCSH.getSatisfiedPoliciesIdentifiers(testAP, crmSecurityRequest, new HashMap<>()).contains(testPolicyId));
        //putting back old credentials
        crmCSH.getSecurityHandler().getAcquiredCredentials().put(SecurityConstants.CORE_AAM_INSTANCE_ID, temp);

        crmCSH.generateServiceResponse();
        //changing platform IPK by changing platform certificate
        X509Certificate cert = getCertificateFromTestKeystore("keystores/core.p12", "core-2");
        when(certificationAuthorityHelper.getAAMCertificate()).thenReturn(cert);
        // attempting authenticate using invalid token
        assertFalse(crmCSH.getSatisfiedPoliciesIdentifiers(testAP, crmSecurityRequest).contains(testPolicyId));
    }

    @Test(expected = SecurityHandlerException.class)
    public void aamCertNotMatchWithKeystoreServiceResponseGenerationIntegrationTest() throws
            SecurityHandlerException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {
        // hack: injecting the AAM running port
        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress);
        String crmKey = "crm";
        String crmComponentId = crmKey + "@" + SecurityConstants.CORE_AAM_INSTANCE_ID;
        // generating the CSH
        IComponentSecurityHandler crmCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                crmComponentId,
                serverAddress,
                AAMOwnerUsername,
                AAMOwnerPassword
        );
        assertNotNull(crmCSH);
        // getting a CRM service response
        assertNotNull(crmCSH.generateServiceResponse());

        //changing platform IPK by changing platform certificate
        X509Certificate cert = getCertificateFromTestKeystore("keystores/core.p12", "core-2");
        when(certificationAuthorityHelper.getAAMCertificate()).thenReturn(cert);
        crmCSH.generateServiceResponse();
    }

    @Test
    public void checkAAMCertWithKeystoreOnCSHCreationIntegrationTestSuccess() throws
            SecurityHandlerException {
        // hack: injecting the AAM running port
        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress);
        String crmKey = "crm";
        String crmComponentId = crmKey + "@" + SecurityConstants.CORE_AAM_INSTANCE_ID;
        // generating the CSH
        IComponentSecurityHandler crmCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                crmComponentId,
                serverAddress,
                AAMOwnerUsername,
                AAMOwnerPassword
        );
        assertNotNull(crmCSH);
        assertNotNull(crmCSH.generateServiceResponse());
        // checking if no error if no changes in certificate
        crmCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                crmComponentId,
                serverAddress,
                AAMOwnerUsername,
                AAMOwnerPassword
        );
        // getting a CRM service response
        assertNotNull(crmCSH);
        assertNotNull(crmCSH.generateServiceResponse());
    }

    @Test(expected = SecurityHandlerException.class)
    public void checkAAMCertWithKeystoreOnCSHCreationIntegrationTestFail() throws
            SecurityHandlerException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {
        // hack: injecting the AAM running port
        ReflectionTestUtils.setField(aamServices, "coreAAMAddress", serverAddress);
        String crmKey = "crm";
        String crmComponentId = crmKey + "@" + SecurityConstants.CORE_AAM_INSTANCE_ID;
        // generating the CSH
        IComponentSecurityHandler crmCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                crmComponentId,
                serverAddress,
                AAMOwnerUsername,
                AAMOwnerPassword
        );

        assertNotNull(crmCSH);
        assertNotNull(crmCSH.generateServiceResponse());
        //changing platform IPK by changing platform certificate
        X509Certificate cert = getCertificateFromTestKeystore("keystores/core.p12", "core-2");
        when(certificationAuthorityHelper.getAAMCertificate()).thenReturn(cert);

        ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                crmComponentId,
                serverAddress,
                AAMOwnerUsername,
                AAMOwnerPassword
        );
    }
}
