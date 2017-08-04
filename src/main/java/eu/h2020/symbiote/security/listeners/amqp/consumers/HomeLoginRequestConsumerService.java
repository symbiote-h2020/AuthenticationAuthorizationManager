package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.services.GetTokenService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.security.cert.CertificateException;

/**
 * RabbitMQ Consumer implementation used for Login actions
 *
 */
public class HomeLoginRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(HomeLoginRequestConsumerService.class);
    private GetTokenService getTokenService;


    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel the channel to which this consumer is attached
     */
    public HomeLoginRequestConsumerService(Channel channel,
                                           GetTokenService getTokenService) {
        super(channel);
        this.getTokenService = getTokenService;
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
        String loginReq;
        String response;

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                .Builder()
                .correlationId(properties.getCorrelationId())
                .build();
            try {
                loginReq = om.readValue(message, String.class);

                Token token = getTokenService.getHomeToken(loginReq);
                    response = om.writeValueAsString(token);
                    this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            } catch (InvalidArgumentsException | WrongCredentialsException | JWTCreationException e) {
                    log.error(e);
                    response = (new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal())).toJson();
                    this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            } catch (CertificateException | MalformedJWTException | ValidationException e) {
                log.error(e);
                throw new SecurityException(e.getMessage(), e.getCause());
            }
            log.info("Login Response: sent back");
        } else {
            log.warn("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}