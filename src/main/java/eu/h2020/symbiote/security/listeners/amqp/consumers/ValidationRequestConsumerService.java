package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.*;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.ValidationRequest;
import eu.h2020.symbiote.security.services.CredentialsValidationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

/**
 * RabbitMQ Consumer implementation used for credentials validation actions
 */
public class ValidationRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(ValidationRequestConsumerService.class);
    private CredentialsValidationService credentialsValidationService;


    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel the channel to which this consumer is attached
     */
    public ValidationRequestConsumerService(Channel channel,
                                            CredentialsValidationService credentialsValidationService) {
        super(channel);
        this.credentialsValidationService = credentialsValidationService;
    }

    /**
     * Called when a <code><b>basic.deliver</b></code> is received for this consumer.
     *
     * @param consumerTag the <i>consumer tag</i> associated with the consumer
     * @param envelope    packaging data for the message
     * @param properties  content header data for the message
     * @param body        the message body (opaque, client-specific byte array)
     * @throws IOException if the consumer encounters an I/O error while processing the message
     * @see Envelope
     */
    @Override
    public void handleDelivery(String consumerTag, Envelope envelope,
                               AMQP.BasicProperties properties, byte[] body)
            throws IOException {

        String message = new String(body, "UTF-8");
        ObjectMapper om = new ObjectMapper();
        ValidationRequest validationRequest;
        String response;

        log.debug("[x] Received Validation Request");

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            validationRequest = om.readValue(message, ValidationRequest.class);

            ValidationStatus validationResponse = null;

            try {
                validationResponse = credentialsValidationService.validate(
                        validationRequest.getToken(),
                        validationRequest.getClientCertificate(),
                        validationRequest.getClientCertificateSigningAAMCertificate(),
                        validationRequest.getForeignTokenIssuingAAMCertificate()
                );
            } catch (TimeoutException | WrongCredentialsException ignored) {

            }

            response = om.writeValueAsString(validationResponse);
            this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());

            log.debug("Validation Status Response: sent back");
        } else {
            log.error("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}