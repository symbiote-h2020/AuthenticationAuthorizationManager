package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.Set;

/**
 * RabbitMQ Consumer implementation used for providing owned platform instances details for the platform owners
 * through Administration module
 * <p>
 */
@Profile("core")
@Component
public class OwnedPlatformDetailsRequestConsumerService {

    private static Log log = LogFactory.getLog(OwnedPlatformDetailsRequestConsumerService.class);
    @Autowired
    private UserRepository userRepository;
    @Value("${aam.deployment.owner.username}")
    private String adminUsername;
    @Value("${aam.deployment.owner.password}")
    private String adminPassword;
    @Autowired
    private PlatformRepository platformRepository;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.ownedplatformdetails.request}",
                    durable = "${rabbit.exchange.aam.durable}",
                    autoDelete = "${rabbit.exchange.aam.autodelete}",
                    exclusive = "false"),
            exchange = @Exchange(
                    value = "${rabbit.exchange.aam.name}",
                    ignoreDeclarationExceptions = "true",
                    durable = "${rabbit.exchange.aam.durable}",
                    autoDelete = "${rabbit.exchange.aam.autodelete}",
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "${rabbit.exchange.aam.type}"),
            key = "${rabbit.routingKey.ownedplatformdetails.request}"))
    public byte[] ownedPlatformDetailsRequest(byte[] body) {
        try {
            log.debug("[x] Received Owned Platform Details Request");
            byte[] response;
            String message;
            ObjectMapper om = new ObjectMapper();
            try {
                message = new String(body, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                log.error(e);
                response = om.writeValueAsBytes(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value()));
                return response;
            }

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

                // preparing collections
                Set<OwnedPlatformDetails> ownedPlatformDetailsSet = new HashSet<>();
                Set<String> ownedPlatformsIdentifiers = new HashSet<>();

                // do it
                User platformOwner = userRepository.findOne(userManagementRequest.getUserCredentials().getUsername());
                if (platformOwner != null)
                    ownedPlatformsIdentifiers = platformOwner.getOwnedServices();

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
                response = om.writeValueAsBytes(ownedPlatformDetailsSet);
            } catch (UserManagementException | InvalidArgumentsException e) {
                log.error(e);
                response = om.writeValueAsBytes(new ErrorResponseContainer(e.getMessage(), HttpStatus.UNAUTHORIZED.value()));
                return response;
            } catch (IOException e) {
                log.error(e);
                response = om.writeValueAsBytes(new ErrorResponseContainer(e.getMessage(), HttpStatus.BAD_REQUEST.value()));
                return response;
            }
            return response;

        } catch (JsonProcessingException e) {
            log.error("Couldn't convert response to byte[]");
            return new ErrorResponseContainer(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()).toJson().getBytes();
        }
    }
}