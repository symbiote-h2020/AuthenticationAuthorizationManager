package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.LocalAttributesManagementRequest;
import eu.h2020.symbiote.security.repositories.LocalUsersAttributesRepository;
import eu.h2020.symbiote.security.repositories.entities.Attribute;
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

/**
 * Consumer service responsible for Local Attributes Management.
 * To work, LocalAttributesManagementRequest is required.
 * As a return, actual Map<String,String> of LocalAttributes are sent (in case of WRITE operation - after the replacement).
 * In case of error, new ErrorResponseContainer is returned.
 *
 * @author Jakub Toczek
 */
@Component
public class LocalAttributesManagementRequestConsumerService {

    private static Log log = LogFactory.getLog(LocalAttributesManagementRequestConsumerService.class);
    @Autowired
    private LocalUsersAttributesRepository localUsersAttributesRepository;
    @Value("${aam.deployment.owner.username}")
    private String adminUsername;
    @Value("${aam.deployment.owner.password}")
    private String adminPassword;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.manage.attributes}",
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
            key = "${rabbit.routingKey.manage.attributes}"))
    public byte[] localAttributesManagementRequest(byte[] body) {
        try {
            log.debug("[x] Received Local Attributes Management Request");
            String message;
            byte[] response;
            ObjectMapper om = new ObjectMapper();
            try {
                message = new String(body, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                log.error(e);
                response = om.writeValueAsBytes(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value()));
                return response;
            }

            LocalAttributesManagementRequest request;

            try {
                request = om.readValue(message, LocalAttributesManagementRequest.class);


                if (request.getAdminCredentials() == null)
                    throw new InvalidArgumentsException();
                // and if they don't match the admin credentials from properties
                if (!request.getAdminCredentials().getUsername().equals(adminUsername)
                        || !request.getAdminCredentials().getPassword().equals(adminPassword))
                    throw new UserManagementException(HttpStatus.UNAUTHORIZED);

                switch (request.getOperationType()) {
                    case READ:
                        Map<String, String> localAttributes = new HashMap<>();
                        for (Attribute attr : localUsersAttributesRepository.findAll()) {
                            localAttributes.put(attr.getKey(), attr.getValue());
                        }
                        response = om.writeValueAsBytes(localAttributes);
                        break;
                    case WRITE:
                        localUsersAttributesRepository.deleteAll();
                        for (Map.Entry<String, String> entry : request.getAttributes().entrySet()) {
                            localUsersAttributesRepository.save(new Attribute(entry.getKey(), entry.getValue()));
                        }
                        response = om.writeValueAsBytes(request.getAttributes());
                        break;
                    default:
                        throw new InvalidArgumentsException();
                }
            } catch (InvalidArgumentsException | UserManagementException e) {
                log.error(e);
                response = om.writeValueAsBytes(new ErrorResponseContainer(e.getMessage(), e.getStatusCode().value()));
                return response;
            } catch (IOException e) {
                log.error(e);
                response = om.writeValueAsBytes(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value()));
                return response;
            }
            return response;


        } catch (JsonProcessingException e) {
            log.error("Couldn't convert response to byte[]");
            return new ErrorResponseContainer(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()).toJson().getBytes();
        }
    }
}
