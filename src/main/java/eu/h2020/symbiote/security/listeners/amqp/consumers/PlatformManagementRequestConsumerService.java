package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.services.PlatformsManagementService;
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
import java.security.cert.CertificateException;

/**
 * RabbitMQ Consumer implementation used for Platforms' Registration actions
 *
 * @author Maksymilian Marcinowski (PSNC)
 * <p>
 */
@Profile("core")
@Component
public class PlatformManagementRequestConsumerService {

    private static Log log = LogFactory.getLog(PlatformManagementRequestConsumerService.class);
    @Autowired
    private PlatformsManagementService platformsManagementService;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.manage.platform.request}",
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
            key = "${rabbit.routingKey.manage.platform.request}"))

    public Object platformManagement(byte[] body) {

        String message;
        try {
            message = new String(body, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            log.error(e);
            return new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value());
        }
        ObjectMapper om = new ObjectMapper();

        try {
            PlatformManagementRequest request = om.readValue(message, PlatformManagementRequest.class);
            log.debug("[x] Received Platform Management Request for: " + request.getPlatformOwnerCredentials().getUsername());
            return platformsManagementService.authManage(request);
        } catch (SecurityException e) {
            log.error(e);
            return new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal());
        } catch (CertificateException e) {
            log.error(e);
            return new ErrorResponseContainer(e.getMessage(), 500);
        } catch (IOException e) {
            log.error(e);
            return new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.ordinal());
        }


    }
}