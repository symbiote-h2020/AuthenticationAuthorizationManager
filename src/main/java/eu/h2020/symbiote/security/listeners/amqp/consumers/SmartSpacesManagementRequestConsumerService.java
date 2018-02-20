package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.SspManagementRequest;
import eu.h2020.symbiote.security.services.SspManagementService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * RabbitMQ Consumer implementation used for Platforms' Registration actions
 *
 * @author Maksymilian Marcinowski (PSNC)
 * <p>
 */
@Profile("core")
@Component
public class SmartSpacesManagementRequestConsumerService {

    private static Log log = LogFactory.getLog(SmartSpacesManagementRequestConsumerService.class);
    @Autowired
    private SspManagementService sspManagementService;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.manage.ssp.request}",
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
            key = "${rabbit.routingKey.manage.ssp.request}"))

    public byte[] sspManagement(byte[] body) {
        try {
            String message;
            ObjectMapper om = new ObjectMapper();
            try {
                message = new String(body, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                log.error(e);
                return om.writeValueAsBytes(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value()));
            }

            try {
                SspManagementRequest request = om.readValue(message, SspManagementRequest.class);
                log.debug("[x] Received SmartSpace Management Request for: " + request.getSspOwnerCredentials().getUsername());
                return om.writeValueAsBytes(sspManagementService.authManage(request));
            } catch (SecurityException e) {
                log.error(e);
                return om.writeValueAsBytes(new ErrorResponseContainer(e.getMessage(), e.getStatusCode().value()));
            } catch (IOException e) {
                log.error(e);
                return om.writeValueAsBytes(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value()));
            }
        } catch (JsonProcessingException e) {
            log.error("Couldn't convert response to byte[]");
            return new ErrorResponseContainer(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()).toJson().getBytes();
        }
    }
}