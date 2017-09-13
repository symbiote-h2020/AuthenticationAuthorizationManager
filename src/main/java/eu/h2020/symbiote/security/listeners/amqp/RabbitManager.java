package eu.h2020.symbiote.security.listeners.amqp;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.Consumer;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.listeners.amqp.consumers.*;
import eu.h2020.symbiote.security.repositories.FederationRulesRepository;
import eu.h2020.symbiote.security.repositories.LocalUsersAttributesRepository;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.services.*;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import java.io.IOException;
import java.util.concurrent.TimeoutException;


/**
 * Manages AMQP listeners
 * <p>
 */
@Component
public class RabbitManager {

    private static Log log = LogFactory.getLog(RabbitManager.class);

    private final UsersManagementService usersManagementService;
    private final PlatformsManagementService platformsManagementService;
    private final CredentialsValidationService credentialsValidationService;
    private final GetTokenService getTokenService;
    private final UserRepository userRepository;
    private final RevocationService revocationService;
    private final LocalUsersAttributesRepository localUsersAttributesRepository;
    private final FederationRulesRepository federationRulesRepository;
    private final PasswordEncoder passwordEncoder;
    private final PlatformRepository platformRepository;
    private IssuingAuthorityType deploymentType;
    private Connection connection;

    @Value("${aam.deployment.owner.username}")
    private String adminUsername;
    @Value("${aam.deployment.owner.password}")
    private String adminPassword;

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

    @Value("${rabbit.queue.getHomeToken.request}")
    private String getHomeTokenRequestQueue;
    @Value("${rabbit.routingKey.getHomeToken.request}")
    private String getHomeTokenRequestRoutingKey;

    @Value("${rabbit.routingKey.manage.user.request}")
    private String userManagementRequestRoutingKey;
    @Value("${rabbit.queue.manage.user.request}")
    private String userManagementRequestQueue;

    @Value("${rabbit.routingKey.manage.platform.request}")
    private String platformManagementRequestRoutingKey;
    @Value("${rabbit.queue.manage.platform.request}")
    private String platformManagementRequestQueue;

    @Value("${rabbit.routingKey.manage.revocation.request}")
    private String revocationRequestRoutingKey;
    @Value("${rabbit.queue.manage.revocation.request}")
    private String revocationRequestQueue;

    @Value("${rabbit.routingKey.ownedplatformdetails.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    private String ownedPlatformDetailsRequestRoutingKey;
    @Value("${rabbit.queue.ownedplatformdetails.request:defaultOverridenBySpringConfigInCoreEnvironment}")
    private String ownedPlatformDetailsRequestQueue;

    @Value("${rabbit.routingKey.manage.attributes}")
    private String localUsersAttributesManagementRequestRoutingKey;
    @Value("${rabbit.queue.manage.attributes}")
    private String localUsersAttributesManagementRequestQueue;

    @Value("${rabbit.queue.get.user.details}")
    private String getUserDetailsQueue;
    @Value("${rabbit.routingKey.get.user.details}")
    private String getUserDetailsRoutingKey;

    @Value("${rabbit.queue.get.platform.owners.names}")
    private String getPlatformOwnersNamesQueue;
    @Value("${rabbit.routingKey.get.platform.owners.names}")
    private String getPlatformOwnersNamesRoutingKey;
    
    @Value("${rabbit.queue.manage.federation.rule}")
    private String manageFederationRuleQueue;
    @Value("${rabbit.routingKey.manage.federation.rule}")
    private String manageFederationRuleRoutingKey;


    @Autowired
    public RabbitManager(UsersManagementService usersManagementService,
                         RevocationService revocationService,
                         PlatformsManagementService platformsManagementService,
                         CredentialsValidationService credentialsValidationService,
                         GetTokenService getTokenService,
                         UserRepository userRepository,
                         CertificationAuthorityHelper certificationAuthorityHelper,
                         LocalUsersAttributesRepository localUsersAttributesRepository,
			 PasswordEncoder passwordEncoder,
			 FederationRulesRepository federationRulesRepository,
                         PlatformRepository platformRepository) {
        this.usersManagementService = usersManagementService;
        this.revocationService = revocationService;
        this.platformsManagementService = platformsManagementService;
        this.credentialsValidationService = credentialsValidationService;
        this.getTokenService = getTokenService;
        this.userRepository = userRepository;
        this.localUsersAttributesRepository = localUsersAttributesRepository;
	this.passwordEncoder = passwordEncoder;
	this.platformRepository = platformRepository;
        this.federationRulesRepository = federationRulesRepository;
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
            // common
            startConsumerOfGetHomeTokenRequestMessages();
            startConsumerOfLocalAttributesManagementRequest();
            startConsumerOfValidationRequestMessages();
            switch (deploymentType) {
                case PLATFORM:
                    startConsumerOfFederationRuleManagementRequest();
                    break;
                case CORE:
                    startConsumerOfGetOwnedPlatformDetailsRequestMessages();
                    startConsumerOfGetPlatformOwnersNames();
                    startConsumerOfGetUserDetails();
                    startConsumerOfPlatformManagementRequestMessages();
                    startConsumerOfRevocationRequestMessages();
                    startConsumerOfUserManagementRequestMessages();
                    startConsumerOfFederationRuleManagementRequest();
                    break;
                case NULL:
                    throw new SecurityMisconfigurationException("Wrong deployment type");
            }
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
    private void startConsumerOfGetHomeTokenRequestMessages() throws IOException {

        String queueName = this.getHomeTokenRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.getHomeTokenRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for getHomeToken request messages....");

            Consumer consumer = new GetHomeTokenRequestConsumerService(channel, getTokenService);
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
    private void startConsumerOfValidationRequestMessages() throws IOException {

        String queueName = this.validateRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.validateRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for token validation request messages");

            Consumer consumer = new ValidationRequestConsumerService(channel, credentialsValidationService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to user management requests.
     *
     * @throws IOException
     */
    private void startConsumerOfUserManagementRequestMessages() throws IOException {

        String queueName = this.userManagementRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.userManagementRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for users' management request messages");

            Consumer consumer = new UserManagementRequestConsumerService(channel,
                    usersManagementService);
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
    private void startConsumerOfGetUserDetails() throws IOException {

        String queueName = this.getUserDetailsQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.getUserDetailsRoutingKey);

            log.info("Authentication and Authorization Manager waiting for users' details requests messages");

            Consumer consumer = new GetUserDetailsConsumerService(channel, adminUsername, adminPassword,
                    userRepository, passwordEncoder);
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
    private void startConsumerOfGetPlatformOwnersNames() throws IOException {

        String queueName = this.getPlatformOwnersNamesQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.getPlatformOwnersNamesRoutingKey);

            log.info("Authentication and Authorization Manager waiting for platform owners requests messages");

            Consumer consumer = new GetPlatformOwnersNamesConsumerService(channel, adminUsername, adminPassword,
                    platformRepository);
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
    private void startConsumerOfGetOwnedPlatformDetailsRequestMessages() throws IOException {

        String queueName = this.ownedPlatformDetailsRequestQueue;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.ownedPlatformDetailsRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for owned platforms' details requests messages");

            Consumer consumer = new OwnedPlatformDetailsRequestConsumerService(channel, userRepository, adminUsername, adminPassword, platformRepository);

            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Platform Registration requests.
     *
     * @throws IOException
     */
    private void startConsumerOfPlatformManagementRequestMessages() throws IOException {

        String queueName = this.platformManagementRequestQueue;

        Channel channel;
        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.platformManagementRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for platform management requests messages");

            Consumer consumer = new PlatformManagementRequestConsumerService(channel,
                    platformsManagementService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }

    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Revocation requests.
     *
     * @throws IOException
     */
    private void startConsumerOfRevocationRequestMessages() throws IOException {

        String queueName = this.revocationRequestQueue;

        Channel channel;
        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.revocationRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for credentials revocation requests messages");

            Consumer consumer = new RevocationRequestConsumerService(channel,
                    revocationService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }

    }

    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to LocalAttributesManagementRequest requests.
     *
     * @throws IOException
     */
    private void startConsumerOfLocalAttributesManagementRequest() throws IOException {

        String queueName = this.localUsersAttributesManagementRequestQueue;

        Channel channel;
        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.localUsersAttributesManagementRequestRoutingKey);

            log.info("Authentication and Authorization Manager waiting for localAttributesManagementRequests messages");

            Consumer consumer = new LocalAttributesManagementRequestConsumerService(channel,
                    localUsersAttributesRepository, adminUsername, adminPassword);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }

    }

    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to FederationRuleManagement requests.
     *
     * @throws IOException
     */
    private void startConsumerOfFederationRuleManagementRequest() throws IOException {

        String queueName = this.manageFederationRuleQueue;

        Channel channel;
        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, this.AAMExchangeName, this.manageFederationRuleRoutingKey);

            log.info("Authentication and Authorization Manager waiting for FederationRuleManagementRequests messages");

            Consumer consumer = new FederationRuleManagementRequestConsumerService(channel,
                    federationRulesRepository, adminUsername, adminPassword);
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
                // getHomeToken
                channel.queueUnbind(this.getHomeTokenRequestQueue, this.AAMExchangeName,
                        this.getHomeTokenRequestRoutingKey);
                channel.queueDelete(this.getHomeTokenRequestQueue);
                // local attributes management request
                channel.queueUnbind(this.localUsersAttributesManagementRequestQueue, this.AAMExchangeName,
                        this.localUsersAttributesManagementRequestRoutingKey);
                channel.queueDelete(this.localUsersAttributesManagementRequestQueue);
                // validation
                channel.queueUnbind(this.validateRequestQueue, this.AAMExchangeName,
                        this.validateRequestRoutingKey);
                channel.queueDelete(this.validateRequestQueue);
		// federation rule management request
                channel.queueUnbind(this.manageFederationRuleQueue, this.AAMExchangeName,
                        this.manageFederationRuleRoutingKey);
                channel.queueDelete(this.manageFederationRuleQueue);
                // deployment dependent interfaces
                switch (deploymentType) {
                    case PLATFORM:
                        break;
                    case CORE:
                        // user management
                        channel.queueUnbind(this.userManagementRequestQueue, this.AAMExchangeName, this
                                .userManagementRequestRoutingKey);
                        channel.queueDelete(this.userManagementRequestQueue);
                        // platform management
                        channel.queueUnbind(this.platformManagementRequestQueue, this.AAMExchangeName, this
                                .platformManagementRequestRoutingKey);
                        channel.queueDelete(this.platformManagementRequestQueue);
                        // credentials revocation
                        channel.queueUnbind(this.revocationRequestQueue, this.AAMExchangeName, this
                                .revocationRequestRoutingKey);
                        channel.queueDelete(this.revocationRequestQueue);
                        // owned platform details
                        channel.queueUnbind(this.ownedPlatformDetailsRequestQueue, this.AAMExchangeName,
                                this.ownedPlatformDetailsRequestRoutingKey);
                        channel.queueDelete(this.ownedPlatformDetailsRequestQueue);
                        // user details request
                        channel.queueUnbind(this.getUserDetailsQueue, this.AAMExchangeName, this
                                .getUserDetailsRoutingKey);
                        channel.queueDelete(this.getUserDetailsQueue);
                        //  platform owners request
                        channel.queueUnbind(this.getPlatformOwnersNamesQueue, this.AAMExchangeName, this
                                .getPlatformOwnersNamesRoutingKey);
                        channel.queueDelete(this.getPlatformOwnersNamesQueue);
                        // federation rule management request
                        channel.queueUnbind(this.manageFederationRuleQueue, this.AAMExchangeName,
                                this.manageFederationRuleRoutingKey);
                        channel.queueDelete(this.manageFederationRuleQueue);
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