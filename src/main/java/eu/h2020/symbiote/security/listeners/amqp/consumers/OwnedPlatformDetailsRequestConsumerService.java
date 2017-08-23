package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.CoreAttributes;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.OwnedPlatformDetails;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import io.jsonwebtoken.ExpiredJwtException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * RabbitMQ Consumer implementation used for providing owned platform instances details for the platform owners
 * through Administration module
 * <p>
 */
public class OwnedPlatformDetailsRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(OwnedPlatformDetailsRequestConsumerService.class);
    private UserRepository userRepository;
    private ValidationHelper validationHelper;


    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel the channel to which this consumer is attached
     */
    public OwnedPlatformDetailsRequestConsumerService(Channel channel,
                                                      UserRepository userRepository, ValidationHelper validationHelper) {
        super(channel);
        this.userRepository = userRepository;
        this.validationHelper = validationHelper;
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
        Token token;
        String response;


        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            try {
                token = new Token(om.readValue(message, String.class));

                if (validationHelper.validate(token.getToken(), "", "", "") != ValidationStatus.VALID)
                    throw new ValidationException("Token validation failed");

                JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
                //verify that JWT is of type Core as was released by a CoreAAM
                if (Token.Type.HOME == Token.Type.valueOf(claimsFromToken.getTtyp()) && !claimsFromToken.getIss().equals(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID))
                    throw new ValidationException("Provider of the HOME Token is not a CORE AAM");

                // verify that the token contains the platform owner public key
                String userFromToken = token.getClaims().getSubject().split("@")[0];

                // verify that this JWT contains attributes relevant for platform owner
                Map<String, String> attributes = claimsFromToken.getAtt();
                // PO role
                if (!UserRole.PLATFORM_OWNER.toString().equals(attributes.get(CoreAttributes.ROLE.toString())))
                    throw new ValidationException("Missing Platform Owner Role");

                // try to retrieve platform corresponding to this platform owner
                Collection<Platform> ownedPlatforms = userRepository.findOne(userFromToken).getOwnedPlatforms().values();
                if (ownedPlatforms.isEmpty())
                    throw new ValidationException("Couldn't find platforms bound with this user");

                Set<OwnedPlatformDetails> ownedPlatformDetailsSet = new HashSet<>();
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

                // replying with the whole set
                response = om.writeValueAsString(ownedPlatformDetailsSet);
                this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                log.debug("Owned Platforms Details response: sent back");
            } catch (ExpiredJwtException | IOException | MalformedJWTException | ValidationException e) {
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