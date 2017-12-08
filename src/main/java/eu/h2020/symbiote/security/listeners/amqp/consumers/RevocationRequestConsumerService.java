package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.services.RevocationService;
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
 * RabbitMQ Consumer implementation used for Revocation actions
 *
 * @author Jakub Toczek (PSNC)
 * <p>
 */
@Component
public class RevocationRequestConsumerService {

    private static Log log = LogFactory.getLog(RevocationRequestConsumerService.class);
    @Autowired
    private RevocationService revocationService;


    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.manage.revocation.request}",
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
            key = "${rabbit.routingKey.manage.revocation.request}"))
    public Object revocation(byte[] body) {
        Object response;
        String message;
        try {
            message = new String(body, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            log.error(e);
            response = new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value());
            return response;
        }
        ObjectMapper om = new ObjectMapper();
        RevocationRequest request;
        try {
            request = om.readValue(message, RevocationRequest.class);
        } catch (IOException e) {
            log.error(e);
            response = new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value());
            return response;
        }
        log.debug("[x] Received RevocationRequest for: " + request.getCredentials()
                .getUsername());
        response = revocationService.revoke(request);
        return response;
    }
}