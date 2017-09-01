package eu.h2020.symbiote.security.functional;

import com.fasterxml.jackson.core.type.TypeReference;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.FederationRule;
import eu.h2020.symbiote.security.communication.payloads.FederationRuleManagementRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for Core AAM deployment scenarios.
 */
@TestPropertySource("/core.properties")
public class FederatedRulesManagementFunctionalTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(FederatedRulesManagementFunctionalTests.class);
    private final String federationRuleId = "testFederationRule";
    @Value("${rabbit.queue.manage.federation.rule}")
    protected String federationRuleManagementRequestQueue;
    private RpcClient federationRuleManagementOverAMQPClient;


    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        federationRuleManagementOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                federationRuleManagementRequestQueue, 5000);
    }


    @Test
    public void federationRuleCreateOverAMQPSuccess() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                new HashMap<>(),
                new HashMap<>(),
                FederationRuleManagementRequest.OperationType.CREATE);
        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        assertNotNull(responseMap.get(federationRuleId));
        assertNotNull(federationRulesRepository.findOne(federationRuleId));
    }

    @Test
    public void federationRuleReadOneOverAMQPSuccess() throws IOException, TimeoutException {
        //putting proper FederationRule in database
        federationRulesRepository.deleteAll();
        Map<String, String> requiredAttr = new HashMap<>();
        requiredAttr.put("key1", "attribute1");
        Map<String, String> releasedFederatedAttr = new HashMap<>();
        releasedFederatedAttr.put("key2", "attribute2");
        FederationRule federationRule = new FederationRule(federationRuleId, requiredAttr, releasedFederatedAttr);
        federationRulesRepository.save(federationRule);

        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                FederationRuleManagementRequest.OperationType.READ);
        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        assertEquals(1, responseMap.size());
        assertNotNull(responseMap.get(federationRuleId));
        FederationRule receivedRule = responseMap.get(federationRuleId);
        assertTrue(receivedRule.getRequiredAttributes().containsKey("key1"));
        assertTrue(receivedRule.getRequiredAttributes().containsValue("attribute1"));
        assertTrue(receivedRule.getReleasedFederatedAttributes().containsKey("key2"));
        assertTrue(receivedRule.getReleasedFederatedAttributes().containsValue("attribute2"));
    }

    @Test
    public void federationRuleReadAllOverAMQPSuccess() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        Map<String, String> requiredAttr = new HashMap<>();
        requiredAttr.put("key1", "attribute1");
        Map<String, String> releasedFederatedAttr = new HashMap<>();
        releasedFederatedAttr.put("key2", "attribute2");
        FederationRule federationRule = new FederationRule(federationRuleId, requiredAttr, releasedFederatedAttr);
        federationRulesRepository.save(federationRule);
        federationRule = new FederationRule(federationRuleId + "2", requiredAttr, releasedFederatedAttr);
        federationRulesRepository.save(federationRule);

        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                "",
                FederationRuleManagementRequest.OperationType.READ);

        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        assertEquals(2, responseMap.size());
    }

    @Test
    public void federationRuleUpdateOverAMQPSuccess() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        Map<String, String> requiredAttr = new HashMap<>();
        requiredAttr.put("key1", "attribute1");
        Map<String, String> releasedFederatedAttr = new HashMap<>();
        releasedFederatedAttr.put("key2", "attribute2");
        FederationRule federationRule = new FederationRule(federationRuleId, requiredAttr, releasedFederatedAttr);
        federationRulesRepository.save(federationRule);

        Map<String, String> requiredAttrNew = new HashMap<>();
        requiredAttrNew.put("key3", "attribute3");
        Map<String, String> releasedFederatedAttrNew = new HashMap<>();
        releasedFederatedAttrNew.put("key4", "attribute4");

        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                requiredAttrNew,
                releasedFederatedAttrNew,
                FederationRuleManagementRequest.OperationType.UPDATE);

        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        FederationRule receivedRule = responseMap.get(federationRuleId);
        assertTrue(receivedRule.getRequiredAttributes().containsKey("key3"));
        assertTrue(receivedRule.getRequiredAttributes().containsValue("attribute3"));
        assertTrue(receivedRule.getReleasedFederatedAttributes().containsKey("key4"));
        assertTrue(receivedRule.getReleasedFederatedAttributes().containsValue("attribute4"));

        receivedRule = federationRulesRepository.findOne(federationRuleId);
        assertTrue(receivedRule.getRequiredAttributes().containsKey("key3"));
        assertTrue(receivedRule.getRequiredAttributes().containsValue("attribute3"));
        assertTrue(receivedRule.getReleasedFederatedAttributes().containsKey("key4"));
        assertTrue(receivedRule.getReleasedFederatedAttributes().containsValue("attribute4"));
    }

    @Test
    public void federationRuleDeleteOverAMQPSuccess() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        Map<String, String> requiredAttr = new HashMap<>();
        requiredAttr.put("key1", "attribute1");
        Map<String, String> releasedFederatedAttr = new HashMap<>();
        releasedFederatedAttr.put("key2", "attribute2");
        FederationRule federationRule = new FederationRule(federationRuleId, requiredAttr, releasedFederatedAttr);
        federationRulesRepository.save(federationRule);

        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                FederationRuleManagementRequest.OperationType.DELETE);

        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        FederationRule receivedRule = responseMap.get(federationRuleId);
        assertTrue(receivedRule.getRequiredAttributes().containsKey("key1"));
        assertTrue(receivedRule.getRequiredAttributes().containsValue("attribute1"));
        assertTrue(receivedRule.getReleasedFederatedAttributes().containsKey("key2"));
        assertTrue(receivedRule.getReleasedFederatedAttributes().containsValue("attribute2"));
        assertNull(federationRulesRepository.findOne(federationRuleId));
    }

    @Test
    public void federationRuleManagementOverAMQPFailWrongCredentials() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(wrongusername, AAMOwnerPassword),
                federationRuleId,
                FederationRuleManagementRequest.OperationType.READ);

        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        ErrorResponseContainer fail = mapper.readValue(response, ErrorResponseContainer.class);
        assertNotNull(fail);
        log.info("Test Client received this error message instead of token: " + fail.getErrorMessage());
    }

    @Test
    public void federationRuleManagementOverAMQPFailNoCredentials() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                null,
                federationRuleId,
                FederationRuleManagementRequest.OperationType.READ);

        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        ErrorResponseContainer fail = mapper.readValue(response, ErrorResponseContainer.class);
        assertNotNull(fail);
        log.info("Test Client received this error message instead of token: " + fail.getErrorMessage());

    }

    @Test
    public void federationRuleCreateOverAMQPFailFederationRuleIdUsed() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        FederationRule federationRule = new FederationRule(federationRuleId, new HashMap<>(), new HashMap<>());
        federationRulesRepository.save(federationRule);
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                FederationRuleManagementRequest.OperationType.CREATE);
        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        ErrorResponseContainer fail = mapper.readValue(response, ErrorResponseContainer.class);
        assertNotNull(fail);
        log.info("Test Client received this error message instead of token: " + fail.getErrorMessage());
    }

    @Test
    public void federationRuleCreateOverAMQPFailFederationRuleIdEmpty() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                "",
                FederationRuleManagementRequest.OperationType.CREATE);
        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        ErrorResponseContainer fail = mapper.readValue(response, ErrorResponseContainer.class);
        assertNotNull(fail);
        log.info("Test Client received this error message instead of token: " + fail.getErrorMessage());
    }

    @Test
    public void federationRuleDeleteOverAMQPFailFederationRuleIdEmpty() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                "",
                FederationRuleManagementRequest.OperationType.DELETE);
        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        ErrorResponseContainer fail = mapper.readValue(response, ErrorResponseContainer.class);
        assertNotNull(fail);
        log.info("Test Client received this error message instead of token: " + fail.getErrorMessage());
    }

    @Test
    public void federationRuleUpdateOverAMQPFailNoFederationRuleToUpdate() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                FederationRuleManagementRequest.OperationType.UPDATE);
        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        ErrorResponseContainer fail = mapper.readValue(response, ErrorResponseContainer.class);
        assertNotNull(fail);
        log.info("Test Client received this error message instead of token: " + fail.getErrorMessage());
    }

}
