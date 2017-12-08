package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.FederationRule;
import eu.h2020.symbiote.security.communication.payloads.FederationRuleManagementRequest;
import eu.h2020.symbiote.security.repositories.FederationRulesRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

@Component
public class FederationRuleManagementRequestConsumerService {

    private static Log log = LogFactory.getLog(FederationRuleManagementRequestConsumerService.class);
    @Autowired
    private FederationRulesRepository federationRulesRepository;
    @Value("${aam.deployment.owner.username}")
    private String adminUsername;
    @Value("${aam.deployment.owner.password}")
    private String adminPassword;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.manage.federation.rule}",
                    durable = "${rabbit.exchange.aam.durable}",
                    autoDelete = "${rabbit.exchange.aam.autodelete}",
                    exclusive = "false"),
            exchange = @Exchange(
                    value = "${rabbit.exchange.aam.name}",
                    ignoreDeclarationExceptions = "true",
                    durable = "${rabbit.exchange.aam.durable}",
                    autoDelete = "${rabbit.exchange.aam.autodelete}",
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "${rabbit.exchange.aam.type}"),
            key = "${rabbit.routingKey.manage.federation.rule}"))
    public Object federationRuleManagement(byte[] body) {

        String message;
        Object response;
        try {
            message = new String(body, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            log.error(e);
            response = new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.ordinal());
            return response;
        }
        ObjectMapper om = new ObjectMapper();
        FederationRuleManagementRequest request;


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
                    response = federationRulesList;
                    break;
                case CREATE:
                    if (request.getFederationRuleId().isEmpty()) {
                        throw new InvalidArgumentsException();
                    }
                    if (federationRulesRepository.exists(request.getFederationRuleId())) {
                        throw new InvalidArgumentsException("Rule with this id already exists");
                    }
                    FederationRule federationRule = new FederationRule(request.getFederationRuleId(), request.getPlatformIds());
                    federationRulesList.put(request.getFederationRuleId(), federationRule);
                    federationRulesRepository.save(federationRule);
                    response = federationRulesList;
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
                    response = federationRulesList;
                    break;
                case UPDATE:
                    if (request.getFederationRuleId().isEmpty()
                            || !federationRulesRepository.exists(request.getFederationRuleId())) {
                        throw new InvalidArgumentsException();
                    }
                    federationRule = new FederationRule(request.getFederationRuleId(), request.getPlatformIds());
                    federationRulesList.put(request.getFederationRuleId(), federationRule);
                    federationRulesRepository.save(federationRule);
                    response = federationRulesList;
                    break;

                default:
                    throw new InvalidArgumentsException();
            }
        } catch (InvalidArgumentsException | UserManagementException e) {
            log.error(e);
            response = new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal());
            return response;
        } catch (IOException e) {
            log.error(e);
            response = new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.ordinal());
            return response;
        }
        return response;

    }
}
