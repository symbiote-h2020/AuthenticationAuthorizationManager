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
import java.util.HashSet;
import java.util.Set;
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
                new HashSet<>(),
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
        Set<String> platformsId = new HashSet<>();
        platformsId.add(platformId);
        FederationRule federationRule = new FederationRule(federationRuleId, platformsId);
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
        assertTrue(receivedRule.getFederationId().contains(federationRuleId));
        assertTrue(receivedRule.getPlatformIds().contains(platformId));
    }

    @Test
    public void federationRuleReadAllOverAMQPSuccess() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        Set<String> platformsId = new HashSet<>();
        platformsId.add(platformId);
        FederationRule federationRule = new FederationRule(federationRuleId, platformsId);
        federationRulesRepository.save(federationRule);
        platformsId.add(platformId + "2");
        federationRule = new FederationRule(federationRuleId + "2", platformsId);
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
        Set<String> platformsId = new HashSet<>();
        platformsId.add(platformId);
        FederationRule federationRule = new FederationRule(federationRuleId, platformsId);
        federationRulesRepository.save(federationRule);

        Set<String> newPlatformsId = new HashSet<>();
        newPlatformsId.add(platformId + "2");

        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                newPlatformsId,
                FederationRuleManagementRequest.OperationType.UPDATE);

        byte[] response = federationRuleManagementOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (federationRuleManagementRequest).getBytes());
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        FederationRule receivedRule = responseMap.get(federationRuleId);
        assertTrue(receivedRule.getFederationId().contains(federationRuleId));
        assertTrue(receivedRule.getPlatformIds().contains(platformId + "2"));

        receivedRule = federationRulesRepository.findOne(federationRuleId);
        assertTrue(receivedRule.getFederationId().contains(federationRuleId));
        assertTrue(receivedRule.getPlatformIds().contains(platformId + "2"));
    }

    @Test
    public void federationRuleDeleteOverAMQPSuccess() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        Set<String> platformsId = new HashSet<>();
        platformsId.add(platformId);
        FederationRule federationRule = new FederationRule(federationRuleId, platformsId);
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
        assertTrue(receivedRule.getFederationId().contains(federationRuleId));
        assertTrue(receivedRule.getPlatformIds().contains(platformId));
        assertNull(federationRulesRepository.findOne(federationRuleId));
    }

    @Test
    public void federationRuleManagementOverAMQPFailWrongCredentials() throws IOException, TimeoutException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(wrongUsername, AAMOwnerPassword),
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
        FederationRule federationRule = new FederationRule(federationRuleId, new HashSet<>());
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
