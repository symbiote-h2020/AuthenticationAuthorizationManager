package eu.h2020.symbiote.security.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import eu.h2020.symbiote.security.exceptions.custom.UserRegistrationException;
import eu.h2020.symbiote.security.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.payloads.PlatformRegistrationRequest;
import eu.h2020.symbiote.security.payloads.PlatformRegistrationResponse;
import eu.h2020.symbiote.security.services.PlatformRegistrationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

/**
 * RabbitMQ Consumer implementation used for Platforms' Registration actions
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class PlatformRegistrationRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(PlatformRegistrationRequestConsumerService.class);
    private PlatformRegistrationService platformRegistrationService;


    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel the channel to which this consumer is attached
     */
    public PlatformRegistrationRequestConsumerService(Channel channel,
                                                      PlatformRegistrationService
                                                              platformRegistrationService) {
        super(channel);
        this.platformRegistrationService = platformRegistrationService;
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
        PlatformRegistrationRequest request;
        String response;

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            try {
                request = om.readValue(message, PlatformRegistrationRequest.class);
                log.debug("[x] Received Platform Registration Request for: " + request.getAAMOwnerCredentials()
                        .getUsername());
                // this endpoint should only allow registering platform owners
                if (request.getPlatformOwnerDetails().getRole() != UserRole.PLATFORM_OWNER)
                    throw new UserRegistrationException();

                PlatformRegistrationResponse registrationResponse = platformRegistrationService.authRegister
                        (request);
                response = om.writeValueAsString(registrationResponse);
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            } catch (SecurityException e) {
                log.error(e);
                response = (new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal())).toJson();
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            }
            log.debug("Platform Registration Response: sent back");
        } else {
            log.error("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}