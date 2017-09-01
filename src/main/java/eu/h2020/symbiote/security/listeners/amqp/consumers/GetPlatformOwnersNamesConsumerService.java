package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.GetPlatformOwnersRequest;
import eu.h2020.symbiote.security.communication.payloads.GetPlatformOwnersResponse;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.IOException;
import java.util.HashMap;


/**
 * RabbitMQ Consumer implementation used to provide names of owners of requested platforms
 * <p>
 */
public class GetPlatformOwnersNamesConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(OwnedPlatformDetailsRequestConsumerService.class);
    private final PlatformRepository platformRepository;
    private final String adminUsername;
    private final String adminPassword;
    private final PasswordEncoder passwordEncoder;

    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel       the channel to which this consumer is attached
     * @param adminUsername
     * @param adminPassword
     */
    public GetPlatformOwnersNamesConsumerService(Channel channel, String adminUsername, String adminPassword,
                                                 PlatformRepository platformRepository, PasswordEncoder passwordEncoder) {
        super(channel);
        this.platformRepository = platformRepository;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.passwordEncoder = passwordEncoder;
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
        String response;

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            try {
                GetPlatformOwnersRequest platformOwnersRequest = om.readValue(message, GetPlatformOwnersRequest.class);
                Credentials administratorCredentials = platformOwnersRequest.getAdministratorCredentials();

                // Request should contain Administrator credentials as well as at least a set of identifiers to look for
                if (administratorCredentials == null || platformOwnersRequest.getPlatformsIdentifiers() == null)
                    throw new InvalidArgumentsException();

                if (!administratorCredentials.getUsername().equals(adminUsername)
                        || !administratorCredentials.getPassword().equals(adminPassword))
                    throw new UserManagementException(HttpStatus.UNAUTHORIZED);

                GetPlatformOwnersResponse foundPlatformOwners = new GetPlatformOwnersResponse(new HashMap<>(), HttpStatus.OK);

                for (String platformID : platformOwnersRequest.getPlatformsIdentifiers()) {
                    Platform foundPlatform = platformRepository.findOne(platformID);
                    if (foundPlatform != null)
                        foundPlatformOwners.getplatformsOwners().put(platformID, foundPlatform.getPlatformOwner().getUsername());
                }
                response = om.writeValueAsString(foundPlatformOwners);
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                log.debug("Platforms and owners response: sent back");
            } catch (UserManagementException | InvalidArgumentsException e) {
                log.error(e);
                response = om.writeValueAsString(new GetPlatformOwnersResponse(new HashMap<>(), HttpStatus.UNAUTHORIZED));
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            }
        } else {
            log.error("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}