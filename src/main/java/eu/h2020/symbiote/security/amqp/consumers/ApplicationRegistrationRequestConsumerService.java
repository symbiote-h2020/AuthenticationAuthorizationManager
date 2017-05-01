package eu.h2020.symbiote.security.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.*;
import eu.h2020.symbiote.security.commons.json.UserRegistrationRequest;
import eu.h2020.symbiote.security.commons.json.UserRegistrationResponse;
import eu.h2020.symbiote.security.commons.json.ErrorResponseContainer;
import eu.h2020.symbiote.security.services.UserRegistrationService;
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
    private UserRegistrationService userRegistrationService;


    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel the channel to which this consumer is attached
     */
    public ApplicationRegistrationRequestConsumerService(Channel channel,
                                                         UserRegistrationService
                                                                 userRegistrationService) {
        super(channel);
        this.userRegistrationService = userRegistrationService;
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
        UserRegistrationRequest request;
        String response;

        log.debug("[x] Received Application Registration Request: '" + message + "'");

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            try {
                request = om.readValue(message, UserRegistrationRequest.class);
                // this endpoint should only allow registering applications
                if (request.getUserDetails().getRole() != UserRole.APPLICATION)
                    throw new UserRegistrationException();

                UserRegistrationResponse registrationResponse = userRegistrationService.authRegister
                        (request);
                response = om.writeValueAsString(registrationResponse);
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            } catch (OperatorCreationException | NoSuchAlgorithmException | CertificateException |
                    InvalidAlgorithmParameterException | KeyStoreException | NoSuchProviderException |
                    UnrecoverableKeyException e) {
                log.error(message, e);
                response = (new ErrorResponseContainer(e.getMessage(), new UserRegistrationException()
                        .getStatusCode().ordinal())).toJson();
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            } catch (UserRegistrationException | UnauthorizedRegistrationException | ExistingUserException | MissingArgumentsException |
                    WrongCredentialsException e) {
                log.error(e);
                response = (new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal())).toJson();
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            }
            log.debug("Application Registration Response: sent back");
        } else {
            log.error("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}