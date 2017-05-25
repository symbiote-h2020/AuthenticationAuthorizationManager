package eu.h2020.symbiote.security.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.exceptions.aam.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.aam.MissingArgumentsException;
import eu.h2020.symbiote.security.exceptions.aam.WrongCredentialsException;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.services.TokenService;
import eu.h2020.symbiote.security.token.Token;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

/**
 * RabbitMQ Consumer implementation used for Login actions
 */
public class LoginRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(LoginRequestConsumerService.class);
    private TokenService tokenService;


    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel the channel to which this consumer is attached
     */
    public LoginRequestConsumerService(Channel channel,
                                       TokenService tokenService) {
        super(channel);
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
        Credentials loginReq;
        String response;

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                .Builder()
                .correlationId(properties.getCorrelationId())
                .build();
            try {
                loginReq = om.readValue(message, Credentials.class);
                log.debug("[x] Received Login Request by: '" + loginReq.getUsername() + "'");
                try {
                    Token token = tokenService.login(loginReq);
                    response = om.writeValueAsString(token);
                    this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                } catch (MissingArgumentsException | WrongCredentialsException | JWTCreationException e) {
                    log.error(e);
                    response = (new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal())).toJson();
                    this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                }

            } catch (IOException e) {
                log.error(e);
                throw e;
            }

            log.info("Login Response: sent back");
        } else {
            log.warn("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}