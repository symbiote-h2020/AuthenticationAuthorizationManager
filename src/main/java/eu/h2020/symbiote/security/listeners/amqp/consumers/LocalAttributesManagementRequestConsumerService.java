package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.LocalAttributesManagementRequest;
import eu.h2020.symbiote.security.repositories.LocalUsersAttributesRepository;
import eu.h2020.symbiote.security.repositories.entities.Attribute;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Consumer service responsible for Local Attributes Management.
 * To work, LocalAttributesManagementRequest is required.
 * As a return, actual Map<String,String> of LocalAttributes are sent (in case of WRITE operation - after the replacement).
 * In case of error, new ErrorResponseContainer is returned.
 *
 * @author Jakub Toczek
 */
public class LocalAttributesManagementRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(LocalAttributesManagementRequestConsumerService.class);
    private final LocalUsersAttributesRepository localUsersAttributesRepository;
    private final String adminUsername;
    private final String adminPassword;

    public LocalAttributesManagementRequestConsumerService(Channel channel, LocalUsersAttributesRepository localUsersAttributesRepository, String adminUsername, String adminPassword) {
        super(channel);
        this.localUsersAttributesRepository = localUsersAttributesRepository;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
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
        LocalAttributesManagementRequest request;
        String response;

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {
            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            try {
                request = om.readValue(message, LocalAttributesManagementRequest.class);


                if (request.getAdminCredentials() == null)
                    throw new InvalidArgumentsException();
                // and if they match the admin credentials from properties
                if (!request.getAdminCredentials().getUsername().equals(adminUsername)
                        || !request.getAdminCredentials().getPassword().equals(adminPassword))
                    throw new UserManagementException(HttpStatus.UNAUTHORIZED);

                switch (request.getOperationType()) {
                    case READ:
                        Map<String, String> localAttributes = new HashMap();
                        for (Attribute attr : localUsersAttributesRepository.findAll()) {
                            localAttributes.put(attr.getKey(), attr.getValue());
                        }
                        response = om.writeValueAsString(localAttributes);
                        break;
                    case WRITE:
                        localUsersAttributesRepository.deleteAll();
                        for (Map.Entry<String, String> entry : request.getAttributes().entrySet()) {
                            localUsersAttributesRepository.save(new Attribute(entry.getKey(), entry.getValue()));
                        }
                        response = om.writeValueAsString(request.getAttributes());
                        break;
                    default:
                        throw new InvalidArgumentsException();
                }
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                log.debug("Revocation Response: sent back");
            } catch (InvalidArgumentsException | UserManagementException e) {
                response = (new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal())).toJson();
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            }
        } else {
            log.error("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);

    }
}
