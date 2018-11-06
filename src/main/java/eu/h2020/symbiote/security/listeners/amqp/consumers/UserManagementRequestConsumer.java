package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.services.UsersManagementService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * RabbitMQ Consumer implementation used for Users' management actions
 *
 * @author Mikołaj Dobski (PSNC)
 * <p>
 */
@Profile({"core", "platform"})
@Component
public class UserManagementRequestConsumer {

    private static Log log = LogFactory.getLog(UserManagementRequestConsumer.class);
    @Autowired
    private UsersManagementService usersManagementService;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.manage.user.request}",
                    durable = "${rabbit.exchange.aam.durable}",
                    autoDelete = "${rabbit.exchange.aam.autodelete}",
                    arguments = {@Argument(
                            name = "x-message-ttl",
                            value = "${rabbit.message-ttl}",
                            type = "java.lang.Integer")},
                    exclusive = "false"),
            exchange = @Exchange(
                    value = "${rabbit.exchange.aam.name}",
                    ignoreDeclarationExceptions = "true",
                    durable = "${rabbit.exchange.aam.durable}",
                    autoDelete = "${rabbit.exchange.aam.autodelete}",
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "${rabbit.exchange.aam.type}"),
            key = "${rabbit.routingKey.manage.user.request}"))

    public byte[] userManagement(byte[] body) {
        try {
            String message;
            byte[] response;
            ObjectMapper om = new ObjectMapper();
            try {
                message = new String(body, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                log.error(e);
                response = om.writeValueAsString(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value())).getBytes();
                return response;
            }

            UserManagementRequest request;

            try {
                request = om.readValue(message, UserManagementRequest.class);
                log.debug("[x] Received User Management Request for: " + request.getUserDetails()
                        .getCredentials().getUsername() + " on behalf of " + request.getAdministratorCredentials()
                        .getUsername());
                response = om.writeValueAsString(usersManagementService.authManage(request)).getBytes();
            } catch (SecurityException e) {
                log.error(e);
                response = om.writeValueAsString(new ErrorResponseContainer(e.getMessage(), e.getStatusCode().value())).getBytes();
                return response;
            } catch (IOException e) {
                log.error(e);
                response = om.writeValueAsString(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value())).getBytes();
                return response;
            }
            return response;
        } catch (JsonProcessingException e) {
            log.error("Couldn't convert response to byte[]");
            return new ErrorResponseContainer(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()).toJson().getBytes();
        }

    }
}