package eu.h2020.symbiote.security.listeners.amqp;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.Consumer;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.listeners.amqp.consumers.*;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.services.CredentialsValidationService;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.services.PlatformsManagementService;
import eu.h2020.symbiote.security.services.UsersManagementService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import java.io.IOException;
import java.util.concurrent.TimeoutException;

@Component
/**
 * Initiates amqp listeners
 *
 * TODO R3 @Mikołaj update queues to reflect the new operations
 */
public class RabbitManager {

    private static Log log = LogFactory.getLog(RabbitManager.class);

    private final UsersManagementService usersManagementService;
    private final PlatformsManagementService platformsManagementService;
    private final CredentialsValidationService credentialsValidationService;
    private final GetTokenService getTokenService;
    private final UserRepository userRepository;
    private final PlatformRepository platformRepository;

    private IssuingAuthorityType deploymentType;

    @Value("${rabbit.host}")
    private String rabbitHost;
    @Value("${rabbit.username}")
    private String rabbitUsername;
    @Value("${rabbit.password}")
    private String rabbitPassword;
    @Value("${rabbit.exchange.aam.name}")
    private String AAMExchangeName;
    @Value("${rabbit.exchange.aam.type}")
    private String AAMExchangeType;
    @Value("${rabbit.exchange.aam.durable}")
    private boolean AAMExchangeDurable;
    @Value("${rabbit.exchange.aam.autodelete}")
    private boolean AAMExchangeAutodelete;
    @Value("${rabbit.exchange.aam.internal}")
    private boolean AAMExchangeInternal;

    @Value("${rabbit.queue.validate.request}")
    private String validateRequestQueue;
    @Value("${rabbit.routingKey.validate.request}")
    private String validateRequestRoutingKey;

    // TODO R3 rework getHomeToken, do we need guest one here?
    @Value("${rabbit.queue.getHomeToken.request}")
    private String getHomeTokenRequestQueue;
    @Value("${rabbit.routingKey.getHomeToken.request}")
    private String getHomeTokenRequestRoutingKey;

    @Value("${rabbit.routingKey.register.user.request}")
    private String userRegistrationRequestRoutingKey;
    @Value("${rabbit.queue.register.user.request}")
    private String userRegistrationRequestQueue;

    @Value("${rabbit.routingKey.register.platform.request}")
    private String platformRegistrationRequestRoutingKey;
    @Value("${rabbit.queue.register.platform.request}")
    private String platformRegistrationRequestQueue;

    @Value("${rabbit.routingKey.ownedplatformdetails.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    private String ownedPlatformDetailsRequestRoutingKey;
    @Value("${rabbit.queue.ownedplatformdetails.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    private String ownedPlatformDetailsRequestQueue;

    private Connection connection;

    @Autowired
    public RabbitManager(UsersManagementService usersManagementService, PlatformsManagementService
            platformsManagementService, CredentialsValidationService credentialsValidationService, GetTokenService getTokenService, UserRepository userRepository,
                         PlatformRepository platformRepository, CertificationAuthorityHelper
                                 certificationAuthorityHelper) {
        this.usersManagementService = usersManagementService;
        this.platformsManagementService = platformsManagementService;
        this.credentialsValidationService = credentialsValidationService;
        this.getTokenService = getTokenService;
        this.userRepository = userRepository;
        this.platformRepository = platformRepository;

        // setting the deployment type from the provisioned certificate
        deploymentType = certificationAuthorityHelper.getDeploymentType();
    }


    /**
     * Initiates connection with Rabbit server using parameters from Bootstrap Properties
     *
     * @throws IOException
     * @throws TimeoutException
     */
    public Connection getConnection() throws IOException, TimeoutException {
        if (connection == null) {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost(this.rabbitHost);
            factory.setUsername(this.rabbitUsername);
            factory.setPassword(this.rabbitPassword);
            this.connection = factory.newConnection();
        }
        return this.connection;
    }


    /**
     * Closes given channel if it exists and is open.
     *
     * @param channel rabbit channel to close
     */
    private void closeChannel(Channel channel) {
        try {
            if (channel != null && channel.isOpen())
                channel.close();
        } catch (IOException | TimeoutException e) {
            log.error(e);
        }
    }


    /**
     * Method gathers all of the rabbit consumer starter methods
     */
    private void startConsumers() throws SecurityMisconfigurationException {
        try {
            startConsumerOfValidateRequestMessages();
            switch (deploymentType) {
                case PLATFORM:
                    startConsumerOfLoginRequestMessages();
                    break;
                case CORE:
                    startConsumerOfApplicationRegistrationRequestMessages();
                    startConsumerOfPlatformRegistrationRequestMessages();
                    startConsumerOfLoginRequestMessages();
                    startConsumerOfOwnedPlatformDetailsRequestMessages();
                    break;
                case NULL:
                    throw new SecurityMisconfigurationException("Wrong deployment type");
            }
        } catch (InterruptedException | IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Login requests.
     *
     * @throws IOException
     */
    private void startConsumerOfLoginRequestMessages() throws IOException {

        String queueName = this.getHomeTokenRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.getHomeTokenRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for getHomeToken request messages....");

            Consumer consumer = new HomeLoginRequestConsumerService(channel, getTokenService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Login requests.
     *
     * @throws IOException
     */
    private void startConsumerOfValidateRequestMessages() throws IOException {

        String queueName = this.validateRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.validateRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for check token revocation request messages");

            Consumer consumer = new ValidationRequestConsumerService(channel, credentialsValidationService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Application Registration requests.
     *
     * @throws IOException
     */
    private void startConsumerOfApplicationRegistrationRequestMessages() throws IOException {

        String queueName = this.userRegistrationRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.userRegistrationRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for user registration request messages");

            Consumer consumer = new UserRegistrationRequestConsumerService(channel,
                    usersManagementService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }

    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Owned Platform Details requests.
     *
     * @throws IOException
     */
    private void startConsumerOfOwnedPlatformDetailsRequestMessages() throws IOException {

        String queueName = this.ownedPlatformDetailsRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.ownedPlatformDetailsRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for owned platform details requests messages");

            Consumer consumer = new OwnedPlatformDetailsRequestConsumerService(channel, userRepository,
                    platformRepository);

            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Platform Registration requests.
     *
     * @throws InterruptedException
     * @throws IOException
     */
    private void startConsumerOfPlatformRegistrationRequestMessages() throws InterruptedException, IOException {

        String queueName = this.platformRegistrationRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.platformRegistrationRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for platform registration requests messages");

            Consumer consumer = new PlatformRegistrationRequestConsumerService(channel,
                    platformsManagementService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates channel and declares Rabbit exchanges for AAM features.
     * It triggers start of all consumers used in with AAM communication.
     */
    public void init() throws SecurityMisconfigurationException {
        Channel channel = null;

        try {
            getConnection();
        } catch (IOException | TimeoutException e) {
            log.error(e);
        }

        if (connection != null) {
            try {
                channel = this.connection.createChannel();

                channel.exchangeDeclare(this.AAMExchangeName,
                        this.AAMExchangeType,
                        this.AAMExchangeDurable,
                        this.AAMExchangeAutodelete,
                        this.AAMExchangeInternal,
                        null);

                startConsumers();

            } catch (IOException e) {
                log.error(e);
            } finally {
                closeChannel(channel);
            }
        }
    }


    @PreDestroy
    public void cleanup() {

        //FIXME check if there is better exception handling in @predestroy method
        log.info("Rabbit cleaned!");
        try {
            Channel channel;
            if (this.connection != null && this.connection.isOpen()) {
                channel = connection.createChannel();
                // check revocation
                channel.queueUnbind(this.validateRequestQueue, this.AAMExchangeName,
                        this.validateRequestRoutingKey);
                channel.queueDelete(this.validateRequestQueue);
                // deployment dependent interfaces
                switch (deploymentType) {
                    case PLATFORM:
                        // getHomeToken
                        channel.queueUnbind(this.getHomeTokenRequestQueue, this.AAMExchangeName,
                                this.getHomeTokenRequestRoutingKey);
                        channel.queueDelete(this.getHomeTokenRequestQueue);
                        break;
                    case CORE:
                        // user registration
                        channel.queueUnbind(this.userRegistrationRequestQueue, this.AAMExchangeName, this
                                .userRegistrationRequestRoutingKey);
                        channel.queueDelete(this.userRegistrationRequestQueue);
                        // platform registration
                        channel.queueUnbind(this.platformRegistrationRequestQueue, this.AAMExchangeName, this
                                .platformRegistrationRequestRoutingKey);
                        channel.queueDelete(this.platformRegistrationRequestQueue);
                        // getHomeToken
                        channel.queueUnbind(this.getHomeTokenRequestQueue, this.AAMExchangeName,
                                this.getHomeTokenRequestRoutingKey);
                        channel.queueDelete(this.getHomeTokenRequestQueue);
                        // owned platform details
                        channel.queueUnbind(this.ownedPlatformDetailsRequestQueue, this.AAMExchangeName,
                                this.ownedPlatformDetailsRequestRoutingKey);
                        channel.queueDelete(this.ownedPlatformDetailsRequestQueue);
                        break;
                    case NULL:
                        break;
                }

                closeChannel(channel);
                this.connection.close();
            }
        } catch (IOException e) {
            log.error(e);
        }
    }
}