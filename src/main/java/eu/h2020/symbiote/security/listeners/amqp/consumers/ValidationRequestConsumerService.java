package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.ValidationRequest;
import eu.h2020.symbiote.security.services.CredentialsValidationService;
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
 * RabbitMQ Consumer implementation used for credentials validation actions
 */
@Component
public class ValidationRequestConsumerService {

    private static Log log = LogFactory.getLog(ValidationRequestConsumerService.class);
    @Autowired
    private CredentialsValidationService credentialsValidationService;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.validate.request}",
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
            key = "${rabbit.routingKey.validate.request}"))
    public byte[] validation(byte[] body) {
        try {
            log.debug("[x] Received Validation Request");
            String message;
            ObjectMapper om = new ObjectMapper();
            try {
                message = new String(body, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                log.error(e);
                return om.writeValueAsBytes(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value()));
            }

            ValidationRequest validationRequest;

            try {
                validationRequest = om.readValue(message, ValidationRequest.class);
            } catch (IOException e) {
                log.error(e);
                return om.writeValueAsBytes(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value()));
            }

            return om.writeValueAsBytes(credentialsValidationService.validate(
                    validationRequest.getToken(),
                    validationRequest.getClientCertificate(),
                    validationRequest.getClientCertificateSigningAAMCertificate(),
                    validationRequest.getForeignTokenIssuingAAMCertificate()
            ));


        } catch (JsonProcessingException e) {
            log.error("Couldn't convert response to byte[]");
            return new ErrorResponseContainer(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()).toJson().getBytes();
        }
    }
}