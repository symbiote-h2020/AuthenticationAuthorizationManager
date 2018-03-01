package eu.h2020.symbiote.security.functional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.model.mim.InformationModel;
import eu.h2020.symbiote.model.mim.QoSConstraint;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Test suite for Core AAM deployment scenarios.
 */
@TestPropertySource("/core.properties")
public class FederatedManagementFunctionalTests extends
        AbstractAAMTestSuite {

    private final String federationId = "testFederationId";
    private final String federationName = "testFederationName";
    @Autowired
    RabbitTemplate rabbitTemplate;
    private String oldExchange;
    private Federation federation;

    @Before
    public void before() {
        federationsRepository.deleteAll();

        federation = new Federation();
        federation.setId(federationId);
        List<QoSConstraint> qoSConstraintList = new ArrayList<>();
        qoSConstraintList.add(new QoSConstraint());
        federation.setSlaConstraints(qoSConstraintList);
        List<FederationMember> federationMembers = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId(platformId);
        federationMember.setInterworkingServiceURL("url");
        federationMembers.add(federationMember);
        federation.setInformationModel(new InformationModel());
        federation.setMembers(federationMembers);
        federation.setName(federationName);
        federation.setPublic(true);
    }

    @After
    public void after() {
        rabbitTemplate.setExchange(oldExchange);
    }

    @Test
    public void federationCreateOverAMQPSuccess() throws IOException, InterruptedException {
        rabbitTemplate.convertAndSend(rabbitExchangeFederation, federationManagementCreateRoutingKey, convertObjectToJson(federation));
        //wait until rabbit listener adds federation
        Thread.sleep(1000);
        assertTrue(federationsRepository.exists(federationId));
        assertEquals(1, federationsRepository.findOne(federationId).getMembers().size());
        assertTrue(federationsRepository.findOne(federationId).getMembers().get(0).getPlatformId().equals(platformId));
    }

    @Test
    public void federationChangeOverAMQPSuccess() throws IOException, InterruptedException {
        federationsRepository.save(federation);
        //change federation to contain new member
        String newFederationMemberId = "newFederationMemberId";
        FederationMember newFederationMember = new FederationMember();
        newFederationMember.setPlatformId(newFederationMemberId);
        federation.getMembers().clear();
        federation.getMembers().add(newFederationMember);
        federation.setName("new name");

        assertEquals(1, federationsRepository.findOne(federationId).getMembers().size());
        assertFalse(federationsRepository.findOne(federationId).getName().equals("new name"));
        rabbitTemplate.convertAndSend(rabbitExchangeFederation, federationManagementUpdateRoutingKey, convertObjectToJson(federation));
        //wait until rabbit listener adds federation
        Thread.sleep(1000);
        assertTrue(federationsRepository.exists(federationId));
        assertTrue(federationsRepository.findOne(federationId).getName().equals("new name"));
        assertEquals(1, federationsRepository.findOne(federationId).getMembers().size());
        //check if there are proper federation members (their Ids) in repo
        List<String> federationMembersIds = new ArrayList<>();
        federationsRepository.findOne(federationId).getMembers().forEach(x -> federationMembersIds.add(x.getPlatformId()));
        assertTrue(federationMembersIds.contains(newFederationMemberId));
    }

    @Test
    public void federationDeleteOverAMQPSuccess() throws InterruptedException {
        federationsRepository.save(federation);
        //change federation to no members - whole federation will be deleted
        federation.getMembers().clear();

        assertTrue(federationsRepository.exists(federationId));
        rabbitTemplate.convertAndSend(rabbitExchangeFederation, federationManagementDeleteRoutingKey, federationId);
        //wait until rabbit listener remove federation
        Thread.sleep(1000);
        assertFalse(federationsRepository.exists(federationId));
    }

    private String convertObjectToJson(Object obj) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.INDENT_OUTPUT, false);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        return mapper.writeValueAsString(obj);
    }
}
