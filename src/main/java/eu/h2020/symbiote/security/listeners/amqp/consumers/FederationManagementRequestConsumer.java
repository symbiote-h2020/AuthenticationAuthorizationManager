package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.repositories.FederationsRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.stream.Collectors;

@Profile("platform")
@Component
public class FederationManagementRequestConsumer {

    private static Log log = LogFactory.getLog(FederationManagementRequestConsumer.class);
    private ObjectMapper om = new ObjectMapper();
    @Autowired
    private FederationsRepository federationsRepository;

    private static boolean isFederationConsistent(Federation federation) {
        //check of federation consistency - size of members should be the same as size of set of members' platformIds
        return federation.getMembers().size() == federation.getMembers().parallelStream()
                .map(FederationMember::getPlatformId)
                .collect(Collectors.toSet())
                .size();
    }

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue,
            exchange = @Exchange(
                    value = "${rabbit.exchange.federation}",
                    ignoreDeclarationExceptions = "true",
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "topic"),
            key = "${rabbit.routingKey.federation.created}"))
    public void federationCreate(byte[] body) {
        log.debug("[x] Received Federation to create");
        try {
            Federation federation = validateFederationChangeRequest(body);
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
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "topic"),
            key = "${rabbit.routingKey.federation.deleted}"))
    public void federationDelete(byte[] body) {
        log.debug("[x] Received Federation Id to delete");
        try {
            String federationId = new String(body, "UTF-8");
            if (federationId == null
                    || federationId.isEmpty())
                throw new InvalidArgumentsException();

            if (!federationsRepository.exists(federationId)) {
                throw new InvalidArgumentsException("Federation does not exists");
            }
            federationsRepository.delete(federationId);

        } catch (InvalidArgumentsException | UnsupportedEncodingException e) {
            log.error(e);
        }
    }

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue,
            exchange = @Exchange(
                    value = "${rabbit.exchange.federation}",
                    ignoreDeclarationExceptions = "true",
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "topic"),
            key = "${rabbit.routingKey.federation.changed}"))
    public void federationUpdate(byte[] body) {
        log.debug("[x] Received Federation to update");
        try {
            Federation federation = validateFederationChangeRequest(body);
            if (!federationsRepository.exists(federation.getId())) {
                throw new InvalidArgumentsException("Federation doesn't exist.");
            }
            federationsRepository.save(federation);
        } catch (InvalidArgumentsException | IOException e) {
            log.error(e);
        }
    }

    private Federation validateFederationChangeRequest(byte[] body) throws IOException, InvalidArgumentsException {
        String message = new String(body, "UTF-8");
        Federation federation = om.readValue(message, Federation.class);
        if (federation.getId() == null
                || federation.getMembers() == null
                || federation.getId().isEmpty())
            throw new InvalidArgumentsException();
        if (!isFederationConsistent(federation)) {
            throw new InvalidArgumentsException("Some of the Federation Members' platform Ids are duplicated");
        }
        return federation;
    }
}
