package eu.h2020.symbiote.security.functional;

import com.fasterxml.jackson.core.type.TypeReference;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.FederationRule;
import eu.h2020.symbiote.security.communication.payloads.FederationRuleManagementRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

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
    @Autowired
    private RabbitTemplate rabbitTemplate;



    @Test
    public void federationRuleCreateOverAMQPSuccess() throws IOException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                new HashSet<>(),
                FederationRuleManagementRequest.OperationType.CREATE);
        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        // verify response
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        assertNotNull(responseMap.get(federationRuleId));
        assertNotNull(federationRulesRepository.findOne(federationRuleId));
    }

    @Test
    public void federationRuleReadOneOverAMQPSuccess() throws IOException {
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
        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        // verify response
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        assertEquals(1, responseMap.size());
        assertNotNull(responseMap.get(federationRuleId));
        FederationRule receivedRule = responseMap.get(federationRuleId);
        assertTrue(receivedRule.getFederationId().contains(federationRuleId));
        assertTrue(receivedRule.getPlatformIds().contains(platformId));
    }

    @Test
    public void federationRuleReadAllOverAMQPSuccess() throws IOException {
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
        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        // verify response
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        assertEquals(2, responseMap.size());
    }

    @Test
    public void federationRuleUpdateOverAMQPSuccess() throws IOException {
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

        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        // verify response
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        FederationRule receivedRule = responseMap.get(federationRuleId);
        assertTrue(receivedRule.getFederationId().contains(federationRuleId));
        assertTrue(receivedRule.getPlatformIds().contains(platformId + "2"));
    }

    @Test
    public void federationRuleDeleteOverAMQPSuccess() throws IOException {
        federationRulesRepository.deleteAll();
        Set<String> platformsId = new HashSet<>();
        platformsId.add(platformId);
        FederationRule federationRule = new FederationRule(federationRuleId, platformsId);
        federationRulesRepository.save(federationRule);

        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                FederationRuleManagementRequest.OperationType.DELETE);

        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        // verify response
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        FederationRule receivedRule = responseMap.get(federationRuleId);
        assertTrue(receivedRule.getFederationId().contains(federationRuleId));
        assertTrue(receivedRule.getPlatformIds().contains(platformId));
        // verify empty db
        assertNull(federationRulesRepository.findOne(federationRuleId));
    }

    @Test
    public void federationRuleDeleteMembersOverAMQPSuccess() throws IOException {
        federationRulesRepository.deleteAll();
        Set<String> platformsId = new HashSet<>();
        platformsId.add(platformId);
        platformsId.add(platformId + "2");
        FederationRule federationRule = new FederationRule(federationRuleId, platformsId);
        federationRulesRepository.save(federationRule);

        Set<String> membersToRemove = new HashSet<>();
        membersToRemove.add(platformId + "2");

        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                membersToRemove,
                FederationRuleManagementRequest.OperationType.DELETE);

        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        // verify response
        HashMap<String, FederationRule> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, FederationRule>>() {
        });
        FederationRule receivedRule = responseMap.get(federationRuleId);
        assertTrue(receivedRule.getFederationId().contains(federationRuleId));
        assertTrue(receivedRule.getPlatformIds().contains(platformId));
        assertFalse(receivedRule.getPlatformIds().contains(platformId + "2"));
    }

    @Test
    public void federationRuleManagementOverAMQPFailWrongCredentials() throws IOException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(wrongUsername, AAMOwnerPassword),
                federationRuleId,
                FederationRuleManagementRequest.OperationType.READ);

        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        assertNotNull(response);
        ErrorResponseContainer errorResponseContainer = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(HttpStatus.UNAUTHORIZED.value(), errorResponseContainer.getErrorCode());
        log.info("Test Client received this error message instead of token: " + errorResponseContainer.getErrorMessage());
    }

    @Test
    public void federationRuleManagementOverAMQPFailNoCredentials() throws IOException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                null,
                federationRuleId,
                FederationRuleManagementRequest.OperationType.READ);

        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        assertNotNull(response);
        ErrorResponseContainer errorResponseContainer = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponseContainer.getErrorCode());
        log.info("Test Client received this error message instead of token: " + errorResponseContainer.getErrorMessage());

    }

    @Test
    public void federationRuleCreateOverAMQPFailFederationRuleIdUsed() throws IOException {
        federationRulesRepository.deleteAll();
        FederationRule federationRule = new FederationRule(federationRuleId, new HashSet<>());
        federationRulesRepository.save(federationRule);
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                FederationRuleManagementRequest.OperationType.CREATE);
        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        assertNotNull(response);
        ErrorResponseContainer errorResponseContainer = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponseContainer.getErrorCode());
        log.info("Test Client received this error message instead of token: " + errorResponseContainer.getErrorMessage());
    }

    @Test
    public void federationRuleCreateOverAMQPFailFederationRuleIdEmpty() throws IOException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                "",
                FederationRuleManagementRequest.OperationType.CREATE);
        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        assertNotNull(response);
        ErrorResponseContainer errorResponseContainer = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponseContainer.getErrorCode());
        log.info("Test Client received this error message instead of token: " + errorResponseContainer.getErrorMessage());
    }

    @Test
    public void federationRuleDeleteOverAMQPFailFederationRuleIdEmpty() throws IOException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                "",
                FederationRuleManagementRequest.OperationType.DELETE);
        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        assertNotNull(response);
        ErrorResponseContainer errorResponseContainer = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponseContainer.getErrorCode());
        log.info("Test Client received this error message instead of token: " + errorResponseContainer.getErrorMessage());
    }

    @Test
    public void federationRuleUpdateOverAMQPFailNoFederationRuleToUpdate() throws IOException {
        federationRulesRepository.deleteAll();
        FederationRuleManagementRequest federationRuleManagementRequest = new FederationRuleManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                federationRuleId,
                FederationRuleManagementRequest.OperationType.UPDATE);
        byte[] response = rabbitTemplate.sendAndReceive(federationRuleManagementRequestQueue, new Message(mapper.writeValueAsBytes(federationRuleManagementRequest), new MessageProperties())).getBody();
        assertNotNull(response);
        ErrorResponseContainer errorResponseContainer = mapper.readValue(response, ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), errorResponseContainer.getErrorCode());
        log.info("Test Client received this error message instead of token: " + errorResponseContainer.getErrorMessage());

    }

}
