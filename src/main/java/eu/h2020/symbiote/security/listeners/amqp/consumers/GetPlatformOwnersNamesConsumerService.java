package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.GetPlatformOwnersRequest;
import eu.h2020.symbiote.security.communication.payloads.GetPlatformOwnersResponse;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;


/**
 * RabbitMQ Consumer implementation used to provide names of owners of given platforms
 * <p>
 */
@Profile("core")
@Component
public class GetPlatformOwnersNamesConsumerService {

    private static Log log = LogFactory.getLog(OwnedPlatformDetailsRequestConsumerService.class);
    @Autowired
    private PlatformRepository platformRepository;
    @Value("${aam.deployment.owner.username}")
    private String adminUsername;
    @Value("${aam.deployment.owner.password}")
    private String adminPassword;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.get.platform.owners.names:defaultOverridenBySpringConfigInCoreEnvironment}",
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
            key = "${rabbit.routingKey.get.platform.owners.names:defaultOverridenBySpringConfigInCoreEnvironment}"))
    public Object getPlatformOwnersNames(byte[] body) {

        Object response;
        String message;
        try {
            message = new String(body, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            log.error(e);
            response = new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.ordinal());
            return response;
        }
        ObjectMapper om = new ObjectMapper();

        try {
            GetPlatformOwnersRequest platformOwnersRequest = om.readValue(message, GetPlatformOwnersRequest.class);
            Credentials administratorCredentials = platformOwnersRequest.getAdministratorCredentials();

            // Request should contain Administrator credentials as well as at least a set of identifiers to look for
            if (administratorCredentials == null || platformOwnersRequest.getPlatformsIdentifiers() == null)
                throw new InvalidArgumentsException();

            if (!administratorCredentials.getUsername().equals(adminUsername)
                    || !administratorCredentials.getPassword().equals(adminPassword))
                throw new UserManagementException(HttpStatus.UNAUTHORIZED);

            GetPlatformOwnersResponse foundPlatformOwners = new GetPlatformOwnersResponse(new HashMap<>(), HttpStatus.OK);

            for (String platformID : platformOwnersRequest.getPlatformsIdentifiers()) {
                Platform foundPlatform = platformRepository.findOne(platformID);
                if (foundPlatform != null)
                    foundPlatformOwners.getplatformsOwners().put(platformID, foundPlatform.getPlatformOwner().getUsername());
            }
            response = foundPlatformOwners;

        } catch (UserManagementException | InvalidArgumentsException e) {
            log.error(e);
            response = new GetPlatformOwnersResponse(new HashMap<>(), HttpStatus.UNAUTHORIZED);
            return response;
        } catch (IOException e) {
            log.error(e);
            response = new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.ordinal());
            return response;
        }

        return response;
    }
}