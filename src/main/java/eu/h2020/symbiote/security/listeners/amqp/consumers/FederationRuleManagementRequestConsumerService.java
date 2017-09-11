package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.FederationRule;
import eu.h2020.symbiote.security.communication.payloads.FederationRuleManagementRequest;
import eu.h2020.symbiote.security.repositories.FederationRulesRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class FederationRuleManagementRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(FederationRuleManagementRequestConsumerService.class);
    private final FederationRulesRepository federationRulesRepository;
    private final String adminUsername;
    private final String adminPassword;

    public FederationRuleManagementRequestConsumerService(Channel channel, FederationRulesRepository federationRulesRepository, String adminUsername, String adminPassword) {
        super(channel);
        this.federationRulesRepository = federationRulesRepository;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
    }

    /**
     * Called when a <code><b>basic.deliver</b></code> is received for this consumer.
     *
     * @param consumerTag the <i>consumer tag</i> associated with the consumer
     * @param envelope    packaging data for the message
     * @param properties  content header data for the message
     * @param body        the message body (opaque, client-specific byte array)
     * @throws IOException if the consumer encounters an I/O error while processing the message
     * @see Envelope
     */
    @Override
    public void handleDelivery(String consumerTag, Envelope envelope,
                               AMQP.BasicProperties properties, byte[] body)
            throws IOException {

        String message = new String(body, "UTF-8");
        ObjectMapper om = new ObjectMapper();
        FederationRuleManagementRequest request;
        String response;

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {
            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            try {
                request = om.readValue(message, FederationRuleManagementRequest.class);
                if (request.getAdminCredentials() == null
                        || request.getFederationRuleId() == null
                        || request.getOperationType() == null
                        || request.getPlatformIds() == null)
                    throw new InvalidArgumentsException();
                // and if they don't match the admin credentials from properties
                if (!request.getAdminCredentials().getUsername().equals(adminUsername)
                        || !request.getAdminCredentials().getPassword().equals(adminPassword))
                    throw new UserManagementException(HttpStatus.UNAUTHORIZED);

                Map<String, FederationRule> federationRulesList = new HashMap<>();

                switch (request.getOperationType()) {
                    case READ:
                        if (request.getFederationRuleId().isEmpty()) {
                            for (FederationRule federationRule : federationRulesRepository.findAll()) {
                                federationRulesList.put(federationRule.getFederationId(), federationRule);
                            }
                        } else {
                            FederationRule federationRule = federationRulesRepository.findOne(request.getFederationRuleId());
                            if (federationRule != null) {
                                federationRulesList.put(federationRule.getFederationId(), federationRule);
                            }
                        }
                        response = om.writeValueAsString(federationRulesList);
                        break;
                    case CREATE:
                        if (request.getFederationRuleId().isEmpty()) {
                            throw new InvalidArgumentsException();
                        }
                        if (federationRulesRepository.findOne(request.getFederationRuleId()) != null) {
                            throw new InvalidArgumentsException("Rule with this id already exists");
                        }
                        FederationRule federationRule = new FederationRule(request.getFederationRuleId(), request.getPlatformIds());
                        federationRulesList.put(request.getFederationRuleId(), federationRule);
                        federationRulesRepository.save(federationRule);
                        response = om.writeValueAsString(federationRulesList);
                        break;

                    case DELETE:
                        if (request.getFederationRuleId().isEmpty()) {
                            throw new InvalidArgumentsException();
                        }
                        federationRule = federationRulesRepository.findOne(request.getFederationRuleId());
                        if (federationRule != null) {
                            if (request.getPlatformIds().isEmpty()) {
                                federationRulesList.put(request.getFederationRuleId(), federationRule);
                                federationRulesRepository.delete(request.getFederationRuleId());
                            } else {
                                for (String id : request.getPlatformIds()) {
                                    federationRule.deletePlatform(id);
                                }
                                federationRulesList.put(request.getFederationRuleId(), federationRule);
                                federationRulesRepository.save(federationRule);
                            }
                        }
                        response = om.writeValueAsString(federationRulesList);
                        break;
                    case UPDATE:
                        if (request.getFederationRuleId().isEmpty()
                                || federationRulesRepository.findOne(request.getFederationRuleId()) == null) {
                            throw new InvalidArgumentsException();
                        }
                        federationRule = new FederationRule(request.getFederationRuleId(), request.getPlatformIds());
                        federationRulesList.put(request.getFederationRuleId(), federationRule);
                        federationRulesRepository.save(federationRule);
                        response = om.writeValueAsString(federationRulesList);
                        break;

                    default:
                        throw new InvalidArgumentsException();
                }
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                log.debug("Federation rules management response: sent back");
            } catch (InvalidArgumentsException | UserManagementException e) {
                response = (new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal())).toJson();
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            }
        } else {
            log.error("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);

    }
}
