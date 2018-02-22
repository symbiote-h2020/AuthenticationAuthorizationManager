package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.repositories.FederationsRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class FederationManagementRequestConsumersService {

    private static Log log = LogFactory.getLog(FederationManagementRequestConsumersService.class);
    @Autowired
    private FederationsRepository federationsRepository;
    @Value("${aam.deployment.owner.username}")
    private String adminUsername;
    @Value("${aam.deployment.owner.password}")
    private String adminPassword;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue,
            exchange = @Exchange(
                    value = "${rabbit.exchange.federation}",
                    ignoreDeclarationExceptions = "true",
                    durable = "false",
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "topic"),
            key = "${rabbit.routingKey.federation.created}"))
    public void federationCreate(String message) {
        log.debug("[x] Received Federation to create");
        ObjectMapper om = new ObjectMapper();

        Federation federation;
        try {
            federation = om.readValue(message, Federation.class);
            if (federation.getId() == null
                    || federation.getMembers() == null
                    || federation.getId().isEmpty())
                throw new InvalidArgumentsException();

            if (federationsRepository.exists(federation.getId())) {
                throw new InvalidArgumentsException("Federation already exists.");
            }
            federationsRepository.save(federation);

        } catch (InvalidArgumentsException | IOException e) {
            log.error(e.getMessage());
        }
    }

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue,
            exchange = @Exchange(
                    value = "${rabbit.exchange.federation}",
                    ignoreDeclarationExceptions = "true",
                    durable = "false",
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "topic"),
            key = "${rabbit.routingKey.federation.changed}"))
    public void federationUpdate(String message) {
        log.debug("[x] Received Federation to update");
        ObjectMapper om = new ObjectMapper();
        Federation federation;
        try {
            federation = om.readValue(message, Federation.class);
            if (federation.getId() == null
                    || federation.getMembers() == null
                    || federation.getId().isEmpty())
                throw new InvalidArgumentsException();
            if (!federationsRepository.exists(federation.getId())) {
                throw new InvalidArgumentsException("Federation doesn't exist.");
            }
            federationsRepository.save(federation);

        } catch (InvalidArgumentsException | IOException e) {
            log.error(e.getMessage());
        }
    }

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue,
            exchange = @Exchange(
                    value = "${rabbit.exchange.federation}",
                    ignoreDeclarationExceptions = "true",
                    durable = "false",
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "topic"),
            key = "${rabbit.routingKey.federation.deleted}"))
    public void federationDelete(String federationId) {
        log.debug("[x] Received Federation Id to delete");
        try {
            if (federationId == null
                    || federationId.isEmpty())
                throw new InvalidArgumentsException();

            if (!federationsRepository.exists(federationId)) {
                throw new InvalidArgumentsException("Federation does not exists");
            }
            federationsRepository.delete(federationId);

        } catch (InvalidArgumentsException e) {
            log.error(e.getMessage());
        }
    }
}
