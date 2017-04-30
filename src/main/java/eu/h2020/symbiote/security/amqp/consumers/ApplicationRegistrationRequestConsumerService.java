package eu.h2020.symbiote.security.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.commons.exceptions.*;
import eu.h2020.symbiote.security.commons.json.ApplicationRegistrationRequest;
import eu.h2020.symbiote.security.commons.json.ApplicationRegistrationResponse;
import eu.h2020.symbiote.security.commons.json.ErrorResponseContainer;
import eu.h2020.symbiote.security.services.ApplicationRegistrationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * RabbitMQ Consumer implementation used for Applications' Registration actions
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class ApplicationRegistrationRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(ApplicationRegistrationRequestConsumerService.class);
    private ApplicationRegistrationService applicationRegistrationService;


    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel the channel to which this consumer is attached
     */
    public ApplicationRegistrationRequestConsumerService(Channel channel,
                                                         ApplicationRegistrationService
                                                                 applicationRegistrationService) {
        super(channel);
        this.applicationRegistrationService = applicationRegistrationService;
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
        ApplicationRegistrationRequest request;
        String response;

        log.info("[x] Received Application Registration Request: '" + message + "'");

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            try {
                request = om.readValue(message, ApplicationRegistrationRequest.class);
                ApplicationRegistrationResponse registrationResponse = applicationRegistrationService.authRegister
                        (request);
                response = om.writeValueAsString(registrationResponse);
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            } catch (OperatorCreationException | NoSuchAlgorithmException | CertificateException |
                    InvalidAlgorithmParameterException | KeyStoreException | NoSuchProviderException |
                    UnrecoverableKeyException e) {
                log.error(message, e);
                response = (new ErrorResponseContainer(e.getMessage(), new ApplicationRegistrationException()
                        .getStatusCode().ordinal())).toJson();
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            } catch (UnauthorizedRegistrationException | ExistingApplicationException | MissingArgumentsException |
                    WrongCredentialsException e) {
                log.error(e);
                response = (new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal())).toJson();
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            }
            log.info("Application Registration Response: sent back");
        } else {
            log.warn("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}