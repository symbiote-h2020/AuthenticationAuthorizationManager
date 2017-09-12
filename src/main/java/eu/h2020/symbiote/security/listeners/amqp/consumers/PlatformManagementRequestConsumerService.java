package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import eu.h2020.symbiote.security.services.PlatformsManagementService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

/**
 * RabbitMQ Consumer implementation used for Platforms' Registration actions
 *
 * @author Maksymilian Marcinowski (PSNC)
 * <p>
 */
public class PlatformManagementRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(PlatformManagementRequestConsumerService.class);
    private PlatformsManagementService platformsManagementService;


    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel the channel to which this consumer is attached
     */
    public PlatformManagementRequestConsumerService(Channel channel,
                                                    PlatformsManagementService
                                                              platformsManagementService) {
        super(channel);
        this.platformsManagementService = platformsManagementService;
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
        PlatformManagementRequest request;
        String response;

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            try {
                request = om.readValue(message, PlatformManagementRequest.class);
                log.debug("[x] Received Platform Management Request for: " + request.getPlatformOwnerCredentials().getUsername());
                PlatformManagementResponse registrationResponse = platformsManagementService.authManage
                        (request);
                response = om.writeValueAsString(registrationResponse);
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            } catch (SecurityException e) {
                log.error(e);
                response = (new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal())).toJson();
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            }
            log.debug("Platform Management Response: sent back");
        } else {
            log.error("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}