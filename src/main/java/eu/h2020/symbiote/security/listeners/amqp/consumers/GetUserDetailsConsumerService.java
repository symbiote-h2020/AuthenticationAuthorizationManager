package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserDetailsResponse;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.IOException;

/**
 * RabbitMQ Consumer implementation used for providing requested user's details
 * <p>
 */
public class GetUserDetailsConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(OwnedPlatformDetailsRequestConsumerService.class);
    private final UserRepository userRepository;
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
    public GetUserDetailsConsumerService(Channel channel, String adminUsername, String adminPassword,
                                         UserRepository userRepository, PasswordEncoder passwordEncoder) {
        super(channel);
        this.userRepository = userRepository;
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
                UserManagementRequest userManagementRequest = om.readValue(message, UserManagementRequest.class);
                Credentials administratorCredentials = userManagementRequest.getAdministratorCredentials();

                // check if we received required administrator credentials and user credentials for API auth
                if (administratorCredentials == null || userManagementRequest.getUserCredentials() == null)
                    throw new InvalidArgumentsException();
                // and if the admin credentials match those from properties
                if (!administratorCredentials.getUsername().equals(adminUsername)
                        || !administratorCredentials.getPassword().equals(adminPassword))
                    throw new UserManagementException(HttpStatus.FORBIDDEN);
                //  begin checking requested user's credentials
                UserDetailsResponse userDetails;
                //  Check if user exists in database
                if (!(userRepository.exists(userManagementRequest.getUserCredentials().getUsername()))) {
                    //  If not then return appropriate message
                    userDetails = new UserDetailsResponse(HttpStatus.BAD_REQUEST, new UserDetails());
                } else {   //  User IS in database
                    User foundUser = userRepository.findOne(userManagementRequest.getUserCredentials().getUsername());
                    //  Checking User's credentials
                    if (passwordEncoder.matches(userManagementRequest.getUserCredentials().getPassword(), foundUser.getPasswordEncrypted())) {
                        userDetails = new UserDetailsResponse(
                                HttpStatus.OK, new UserDetails(new Credentials(foundUser.getUsername(), ""), "", foundUser.getRecoveryMail(),
                                foundUser.getRole(), foundUser.getAttributes(), foundUser.getClientCertificates())
                        );
                    } else
                        //  If wrong password was provided return message with UNAUTHORIZED status
                        userDetails = new UserDetailsResponse(HttpStatus.UNAUTHORIZED, new UserDetails());
                }
                response = om.writeValueAsString(userDetails);
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                log.debug("User Details response: sent back");
            } catch (UserManagementException | InvalidArgumentsException e) {
                log.error(e);
                if (e.getClass() == InvalidArgumentsException.class)    // Missing Admin or User credentials
                    response = om.writeValueAsString(new UserDetailsResponse(HttpStatus.UNAUTHORIZED, new UserDetails()));
                else    //  Incorrect Admin login / password
                    response = om.writeValueAsString(new UserDetailsResponse(HttpStatus.FORBIDDEN, new UserDetails()));
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            }
        } else {
            log.error("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}