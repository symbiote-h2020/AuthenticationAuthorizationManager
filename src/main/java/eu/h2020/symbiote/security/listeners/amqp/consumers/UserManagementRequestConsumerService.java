package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.services.UsersManagementService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
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
@Component
public class UserManagementRequestConsumerService {

    private static Log log = LogFactory.getLog(UserManagementRequestConsumerService.class);
    @Autowired
    private UsersManagementService usersManagementService;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.manage.user.request}",
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
            key = "${rabbit.routingKey.manage.user.request}"))
    public Object userManagement(byte[] body) {

        String message;
        Object response;
        try {
            message = new String(body, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            log.error(e);
            response = new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value());
            return response;
        }
        ObjectMapper om = new ObjectMapper();
        UserManagementRequest request;

        try {
            request = om.readValue(message, UserManagementRequest.class);
            log.debug("[x] Received User Management Request for: " + request.getUserDetails()
                    .getCredentials().getUsername() + " on behalf of " + request.getAdministratorCredentials()
                    .getUsername());
            response = usersManagementService.authManage(request);
        } catch (SecurityException e) {
            log.error(e);
            response = new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal());
            return response;
        } catch (IOException e) {
            log.error(e);
            response = new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value());
            return response;
        }
        return response;
    }
}