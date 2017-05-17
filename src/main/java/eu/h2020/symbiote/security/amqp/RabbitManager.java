package eu.h2020.symbiote.security.amqp;

import com.rabbitmq.client.*;
import eu.h2020.symbiote.security.amqp.consumers.*;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.exceptions.aam.AAMMisconfigurationException;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.services.LoginService;
import eu.h2020.symbiote.security.services.PlatformRegistrationService;
import eu.h2020.symbiote.security.services.TokenService;
import eu.h2020.symbiote.security.services.UserRegistrationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import java.io.IOException;
import java.util.concurrent.TimeoutException;

@Component
public class RabbitManager {

    private static Log log = LogFactory.getLog(RabbitManager.class);

    private final UserRegistrationService userRegistrationService;
    private final PlatformRegistrationService platformRegistrationService;
    private final LoginService loginService;
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final PlatformRepository platformRepository;
    private final RegistrationManager registrationManager;

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

    @Value("${rabbit.queue.check_token_revocation.request}")
    private String checkTokenRevocationRequestQueue;
    @Value("${rabbit.routingKey.check_token_revocation.request}")
    private String checkTokenRevocationRequestRoutingKey;

    @Value("${rabbit.queue.login.request}")
    private String loginRequestQueue;
    @Value("${rabbit.routingKey.login.request}")
    private String loginRequestRoutingKey;

    @Value("${rabbit.routingKey.register.app.request}")
    private String applicationRegistrationRequestRoutingKey;
    @Value("${rabbit.queue.register.app.request}")
    private String applicationRegistrationRequestQueue;

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
    public RabbitManager(UserRegistrationService userRegistrationService, PlatformRegistrationService
            platformRegistrationService, LoginService loginService,
                         TokenService tokenService, UserRepository userRepository, PlatformRepository
                                 platformRepository, RegistrationManager registrationManager) {
        this.userRegistrationService = userRegistrationService;
        this.platformRegistrationService = platformRegistrationService;
        this.loginService = loginService;
        this.tokenService = tokenService;
        this.userRepository = userRepository;
        this.platformRepository = platformRepository;
        this.registrationManager = registrationManager;

        // setting the deployment type from the provisioned certificate
        deploymentType = registrationManager.getDeploymentType();
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
    private void startConsumers() throws AAMMisconfigurationException {
        try {
            startConsumerOfCheckTokenRevocationRequestMessages();
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
                    throw new AAMMisconfigurationException("Wrong deployment type");
            }
        } catch (InterruptedException | IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Login requests.
     *
     * @throws InterruptedException
     * @throws IOException
     */
    private void startConsumerOfLoginRequestMessages() throws InterruptedException, IOException {

        String queueName = this.loginRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.loginRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for login request messages....");

            Consumer consumer = new LoginRequestConsumerService(channel, loginService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Login requests.
     *
     * @throws InterruptedException
     * @throws IOException
     */
    private void startConsumerOfCheckTokenRevocationRequestMessages() throws InterruptedException, IOException {

        String queueName = this.checkTokenRevocationRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.checkTokenRevocationRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for check token revocation request messages");

            Consumer consumer = new CheckTokenRevocationRequestConsumerService(channel, tokenService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Application Registration requests.
     *
     * @throws InterruptedException
     * @throws IOException
     */
    private void startConsumerOfApplicationRegistrationRequestMessages() throws InterruptedException, IOException {

        String queueName = this.applicationRegistrationRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.applicationRegistrationRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for application registration request messages");

            Consumer consumer = new ApplicationRegistrationRequestConsumerService(channel,
                    userRegistrationService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }

    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Owned Platform Details requests.
     *
     * @throws InterruptedException
     * @throws IOException
     */
    private void startConsumerOfOwnedPlatformDetailsRequestMessages() throws InterruptedException, IOException {

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
                    platformRegistrationService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates channel and declares Rabbit exchanges for AAM features.
     * It triggers start of all consumers used in with AAM communication.
     */
    public void init() throws AAMMisconfigurationException {
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
                channel.queueUnbind(this.checkTokenRevocationRequestQueue, this.AAMExchangeName,
                        this.checkTokenRevocationRequestRoutingKey);
                channel.queueDelete(this.checkTokenRevocationRequestQueue);
                // deployment dependent interfaces
                switch (deploymentType) {
                    case PLATFORM:
                        // login
                        channel.queueUnbind(this.loginRequestQueue, this.AAMExchangeName,
                                this.loginRequestRoutingKey);
                        channel.queueDelete(this.loginRequestQueue);
                        break;
                    case CORE:
                        // application registration
                        channel.queueUnbind(this.applicationRegistrationRequestQueue, this.AAMExchangeName, this
                                .applicationRegistrationRequestRoutingKey);
                        channel.queueDelete(this.applicationRegistrationRequestQueue);
                        // platform registration
                        channel.queueUnbind(this.platformRegistrationRequestQueue, this.AAMExchangeName, this
                                .platformRegistrationRequestRoutingKey);
                        channel.queueDelete(this.platformRegistrationRequestQueue);
                        // login
                        channel.queueUnbind(this.loginRequestQueue, this.AAMExchangeName,
                                this.loginRequestRoutingKey);
                        channel.queueDelete(this.loginRequestQueue);
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


    /**
     * Method publishes given message to the given exchange and routing key.
     * Props are set for correct message handle on the receiver side.
     *
     * @param exchange   name of the proper Rabbit exchange, adequate to topic of the communication
     * @param routingKey name of the proper Rabbit routing key, adequate to topic of the communication
     * @param message    message content in JSON String format
     */
    private void sendMessage(String exchange, String routingKey, String message) {
        AMQP.BasicProperties props;
        Channel channel = null;
        try {
            channel = this.connection.createChannel();
            props = new AMQP.BasicProperties()
                    .builder()
                    .contentType("application/json")
                    .build();

            channel.basicPublish(exchange, routingKey, props, message.getBytes());
        } catch (IOException e) {
            log.error(e);
        } finally {
            closeChannel(channel);
        }
    }
}
