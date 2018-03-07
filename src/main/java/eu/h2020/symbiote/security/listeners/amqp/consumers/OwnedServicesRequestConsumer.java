package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.communication.payloads.OwnedService;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.SmartSpaceRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
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
 * RabbitMQ Consumer implementation used for providing owned services details for the service owners
 * through Administration module
 * <p>
 */
@Profile("core")
@Component
public class OwnedServicesRequestConsumer {

    private static Log log = LogFactory.getLog(OwnedServicesRequestConsumer.class);
    @Autowired
    private UserRepository userRepository;
    @Value("${aam.deployment.owner.username}")
    private String adminUsername;
    @Value("${aam.deployment.owner.password}")
    private String adminPassword;
    @Autowired
    private PlatformRepository platformRepository;
    @Autowired
    private SmartSpaceRepository smartSpaceRepository;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "${rabbit.queue.ownedservices.request}",
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
            key = "${rabbit.routingKey.ownedservices.request}"))
    public byte[] ownedServicesRequest(byte[] body) {
        try {
            log.debug("[x] Received Owned Services Details Request");
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
                Set<OwnedService> ownedServiceSet = new HashSet<>();
                Set<String> ownedServicesIdentifiers = new HashSet<>();

                // do it
                User serviceOwner = userRepository.findOne(userManagementRequest.getUserCredentials().getUsername());
                if (serviceOwner != null)
                    ownedServicesIdentifiers = serviceOwner.getOwnedServices();

                if (!ownedServicesIdentifiers.isEmpty()) {
                    for (String serviceIdentifier : ownedServicesIdentifiers) {
                        if (serviceIdentifier.startsWith(SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX)) {
                            SmartSpace smartSpace = smartSpaceRepository.findOne(serviceIdentifier);
                            if (smartSpace != null) {
                                OwnedService ownedService = new OwnedService(
                                        smartSpace.getInstanceIdentifier(),
                                        smartSpace.getInstanceFriendlyName(),
                                        OwnedService.ServiceType.SMART_SPACE,
                                        "",
                                        smartSpace.getExternalAddress(),
                                        smartSpace.isExposingSiteLocalAddress(),
                                        smartSpace.getSiteLocalAddress(),
                                        smartSpace.getLocalCertificationAuthorityCertificate(),
                                        smartSpace.getComponentCertificates()
                                );
                                ownedServiceSet.add(ownedService);
                            } else {
                                // TODO throw exception as this shows inconsistence in our DB
                            }
                        } else {
                            Platform platform = platformRepository.findOne(serviceIdentifier);
                            if (platform != null) {
                                OwnedService ownedService = new OwnedService(
                                        platform.getPlatformInstanceId(),
                                        platform.getPlatformInstanceFriendlyName(),
                                        OwnedService.ServiceType.PLATFORM,
                                        platform.getPlatformInterworkingInterfaceAddress(),
                                        "",
                                        false,
                                        "",
                                        platform.getPlatformAAMCertificate(),
                                        platform.getComponentCertificates()
                                );
                                ownedServiceSet.add(ownedService);
                            } else {
                                // TODO throw exception as this shows inconsistence in our DB
                            }
                        }
                    }
                }
                // replying with the whole set
                response = om.writeValueAsBytes(ownedServiceSet);
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