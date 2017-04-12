package eu.h2020.symbiote.rabbitmq.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.commons.json.ErrorResponseContainer;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.services.LoginService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

/**
 * RabbitMQ Consumer implementation used for Login actions
 */
public class LoginRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(LoginRequestConsumerService.class);
    private LoginService loginService;


    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel the channel to which this consumer is attached
     */
    public LoginRequestConsumerService(Channel channel,
                                       LoginService loginService) {
        super(channel);
        this.loginService = loginService;
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
        LoginRequest loginReq;
        String response;

        log.info("[x] Received Login Request: '" + message + "'");

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                .Builder()
                .correlationId(properties.getCorrelationId())
                .build();
            try {
                loginReq = om.readValue(message, LoginRequest.class);

                try {
                    RequestToken token = loginService.login(loginReq);
                    response = om.writeValueAsString(token);
                    this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                } catch (MissingArgumentsException | WrongCredentialsException | JWTCreationException e) {
                    response = (new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal())).toJson();
                    this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                }

            } catch (IOException e) {
                e.printStackTrace();
            }

            log.info("Login Response: sent back");
        } else {
            log.warn("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}