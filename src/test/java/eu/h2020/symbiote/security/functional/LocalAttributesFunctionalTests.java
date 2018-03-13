package eu.h2020.symbiote.security.functional;

import com.fasterxml.jackson.core.type.TypeReference;
import eu.h2020.symbiote.security.AbstractAAMAMQPTestSuite;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.LocalAttributesManagementRequest;
import eu.h2020.symbiote.security.repositories.entities.Attribute;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;


@TestPropertySource("/core.properties")
public class LocalAttributesFunctionalTests extends
        AbstractAAMAMQPTestSuite {

    @Value("${rabbit.queue.manage.attributes}")
    protected String attributeManagementRequestQueue;
    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Test
    public void addAttributesOverAMQPSuccess() throws
            IOException {
        localUsersAttributesRepository.deleteAll();
        Map<String, String> attributesMap = new HashMap<>();
        attributesMap.put("key1", "attribute1");
        attributesMap.put("key2", "attribute2");
        LocalAttributesManagementRequest localUsersLocalAttributesManagementRequest = new LocalAttributesManagementRequest(attributesMap, new Credentials(AAMOwnerUsername, AAMOwnerPassword), LocalAttributesManagementRequest.OperationType.WRITE);
        byte[] response = rabbitTemplate.sendAndReceive(attributeManagementRequestQueue, new Message(mapper.writeValueAsBytes
                (localUsersLocalAttributesManagementRequest), new MessageProperties())).getBody();
        HashMap<String, String> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, String>>() {
        });
        assertEquals(2, responseMap.size());
        assertEquals(2, localUsersAttributesRepository.findAll().size());
    }

    @Test
    public void readAttributesOverAMQPSuccess() throws
            IOException {
        localUsersAttributesRepository.deleteAll();
        localUsersAttributesRepository.save(new Attribute("key1", "attribute1"));
        localUsersAttributesRepository.save(new Attribute("key2", "attribute2"));
        LocalAttributesManagementRequest localUsersLocalAttributesManagementRequest = new LocalAttributesManagementRequest(new HashMap<>(), new Credentials(AAMOwnerUsername, AAMOwnerPassword), LocalAttributesManagementRequest.OperationType.READ);
        byte[] response = rabbitTemplate.sendAndReceive(attributeManagementRequestQueue, new Message(mapper.writeValueAsBytes(
                localUsersLocalAttributesManagementRequest), new MessageProperties())).getBody();

        HashMap<String, String> responseMap = mapper.readValue(response, new TypeReference<HashMap<String, String>>() {
        });
        assertEquals("attribute1", responseMap.get("key1"));
        assertEquals("attribute2", responseMap.get("key2"));
    }

    @Test
    public void readAttributesOverAMQPFailWrongCredentials() throws
            IOException {
        LocalAttributesManagementRequest localUsersLocalAttributesManagementRequest = new LocalAttributesManagementRequest(new HashMap<>(),
                new Credentials(username, AAMOwnerPassword),
                LocalAttributesManagementRequest.OperationType.READ);
        byte[] response = rabbitTemplate.sendAndReceive(attributeManagementRequestQueue, new Message(mapper.writeValueAsBytes(
                localUsersLocalAttributesManagementRequest), new MessageProperties())).getBody();

        ErrorResponseContainer fail = mapper.readValue(response, ErrorResponseContainer.class);
        assertNotNull(fail);
        //log.info("Test Client received this error message instead of token: " + fail.getErrorMessage());

    }
}
