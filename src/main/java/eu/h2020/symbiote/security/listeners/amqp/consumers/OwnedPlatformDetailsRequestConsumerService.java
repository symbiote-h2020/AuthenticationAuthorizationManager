package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.OwnedPlatformDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * RabbitMQ Consumer implementation used for providing owned platform instances details for the platform owners
 * through Administration module
 * <p>
 */
public class OwnedPlatformDetailsRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(OwnedPlatformDetailsRequestConsumerService.class);
    private final UserRepository userRepository;
    private final String adminUsername;
    private final String adminPassword;
    private PlatformRepository platformRepository;

    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel            the channel to which this consumer is attached
     * @param adminUsername
     * @param adminPassword
     * @param platformRepository
     */
    public OwnedPlatformDetailsRequestConsumerService(Channel channel,
                                                      UserRepository userRepository, String adminUsername, String adminPassword, PlatformRepository platformRepository) {
        super(channel);
        this.userRepository = userRepository;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.platformRepository = platformRepository;
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
                UserManagementRequest userManagementRequest = om.readValue(message, UserManagementRequest.class);
                Credentials administratorCredentials = userManagementRequest.getAdministratorCredentials();

                // check if we received required administrator credentials for API auth
                if (administratorCredentials == null || userManagementRequest.getUserCredentials().getUsername().isEmpty())
                    throw new InvalidArgumentsException();
                // and if they match the admin credentials from properties
                if (!administratorCredentials.getUsername().equals(adminUsername)
                        || !administratorCredentials.getPassword().equals(adminPassword))
                    throw new UserManagementException(HttpStatus.UNAUTHORIZED);
                // do it
                User platformOwner = userRepository.findOne(userManagementRequest.getUserCredentials().getUsername());
                Set<OwnedPlatformDetails> ownedPlatformDetailsSet = new HashSet<>();
                Set<String> ownedPlatformsIdentifiers = new HashSet<>();

                if (platformOwner != null)
                    ownedPlatformsIdentifiers = platformOwner.getOwnedPlatforms();

                if (!ownedPlatformsIdentifiers.isEmpty()) {
                    Set<Platform> ownedPlatforms = new HashSet<>();
                    for (String platformIdentifier : ownedPlatformsIdentifiers) {
                        Platform platform = platformRepository.findOne(platformIdentifier);
                        if (platform != null)
                            ownedPlatforms.add(platform);
                    }
                    for (Platform ownedPlatform : ownedPlatforms) {
                        OwnedPlatformDetails ownedPlatformDetails = new OwnedPlatformDetails(
                                ownedPlatform.getPlatformInstanceId(),
                                ownedPlatform.getPlatformInterworkingInterfaceAddress(),
                                ownedPlatform.getPlatformInstanceFriendlyName(),
                                ownedPlatform.getPlatformAAMCertificate(),
                                ownedPlatform.getComponentCertificates()
                        );
                        ownedPlatformDetailsSet.add(ownedPlatformDetails);
                    }
                }
                // replying with the whole set
                response = om.writeValueAsString(ownedPlatformDetailsSet);
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                log.debug("Owned Platforms Details response: sent back");
            } catch (UserManagementException | InvalidArgumentsException e) {
                log.error(e);
                response = (new ErrorResponseContainer(e.getMessage(), HttpStatus.UNAUTHORIZED.value()).toJson());
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            }
        } else {
            log.error("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}