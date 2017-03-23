package eu.h2020.symbiote.rabbitmq.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.commons.enums.Status;
import eu.h2020.symbiote.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.commons.json.ErrorResponseContainer;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.rabbitmq.RabbitManager;
import eu.h2020.symbiote.services.LoginService;
import eu.h2020.symbiote.services.TokenService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

/**
 * RabbitMQ Consumer implementation used for token revocation checking actions
 *
 */
public class CheckTokenRevocationRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(CheckTokenRevocationRequestConsumerService.class);
    private RabbitManager rabbitManager;
    private TokenService tokenService;


    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel           the channel to which this consumer is attached
     * @param rabbitManager     rabbit manager bean passed for access to messages manager
     */
    public CheckTokenRevocationRequestConsumerService(Channel channel,
                                                      RabbitManager rabbitManager,
                                                      TokenService tokenService) {
        super(channel);
        this.rabbitManager = rabbitManager;
        this.tokenService = tokenService;
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
        RequestToken requestToken;
        String response;

        log.info("[x] Received Check Token Revocation Request: '" + message + "'");

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            try {
                requestToken = om.readValue(message,RequestToken.class);

                CheckTokenRevocationResponse checkTokenRevocationResponse = tokenService.checkHomeTokenRevocation(requestToken);
                response = om.writeValueAsString(checkTokenRevocationResponse);
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());

            } catch (IOException e) {
                e.printStackTrace();
            }

            log.info("Check Token Revocation Response: sent back");
        } else {
            log.warn("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}