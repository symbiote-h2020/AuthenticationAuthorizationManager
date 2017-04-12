package eu.h2020.symbiote.rabbitmq;

import com.rabbitmq.client.*;
import eu.h2020.symbiote.rabbitmq.consumers.CheckTokenRevocationRequestConsumerService;
import eu.h2020.symbiote.rabbitmq.consumers.LoginRequestConsumerService;
import eu.h2020.symbiote.services.LoginService;
import eu.h2020.symbiote.services.TokenService;
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
    private final LoginService loginService;
    private final TokenService tokenService;
    @Value("${rabbit.host}")
    private String rabbitHost;
    @Value("${rabbit.username}")
    private String rabbitUsername;
    @Value("${rabbit.password}")
    private String rabbitPassword;
    @Value("${rabbit.exchange.platform.name}")
    private String platformExchangeName;
    @Value("${rabbit.exchange.platform.type}")
    private String platformExchangeType;
    @Value("${rabbit.exchange.platform.durable}")
    private boolean plaftormExchangeDurable;
    @Value("${rabbit.exchange.platform.autodelete}")
    private boolean platformExchangeAutodelete;
    @Value("${rabbit.exchange.platform.internal}")
    private boolean platformExchangeInternal;
    @Value("${rabbit.queue.check_token_revocation.request}")
    private String checkTokenRevocationRequestQueue;
    @Value("${rabbit.routingKey.check_token_revocation.request}")
    private String checkTokenRevocationRequestRoutingKey;
    @Value("${rabbit.routingKey.login.request}")
    private String loginRequestRoutingKey;
    @Value("${rabbit.queue.login.request}")
    private String loginRequestQueue;
    private Connection connection;

    @Autowired
    public RabbitManager(LoginService loginService, TokenService tokenService) {
        this.loginService = loginService;
        this.tokenService = tokenService;
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
        } catch (IOException e) {
            e.printStackTrace();
        } catch (TimeoutException e) {
            e.printStackTrace();
        }
    }


    /**
     * Method gathers all of the rabbit consumer starter methods
     */
    public void startConsumers() {
        try {
            startConsumerOfLoginRequestMessages();
            startConsumerOfCheckTokenRevocationRequestMessages();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
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
            channel.queueBind(queueName, this.platformExchangeName, this.loginRequestRoutingKey);
            //channel.basicQos(1); // to spread the load over multiple servers we set the prefetchCount setting

            log.info("Cloud Authentication and Authorization Manager waiting for login request messages....");

            Consumer consumer = new LoginRequestConsumerService(channel, loginService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            e.printStackTrace();
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
            channel.queueBind(queueName, this.platformExchangeName, this.checkTokenRevocationRequestRoutingKey);
            //channel.basicQos(1); // to spread the load over multiple servers we set the prefetchCount setting

            log.info("Cloud Authentication and Authorization Manager waiting for check token revocation request " +
                "messages....");

            Consumer consumer = new CheckTokenRevocationRequestConsumerService(channel, this, tokenService);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public void sendPlatformCreatedMessage(String message) {
        sendMessage(this.platformExchangeName, this.loginRequestRoutingKey, message);
        log.info("- login request message sent");
    }


    /**
     * Method creates channel and declares Rabbit exchanges for Login and Request Foreign Token in CAAM.
     * It triggers start of all consumers used in CAAM communication.
     */
    public void init() {
        Channel channel = null;

        try {
            getConnection();
        } catch (IOException | TimeoutException e) {
            e.printStackTrace();
        }

        if (connection != null) {
            try {
                channel = this.connection.createChannel();

                channel.exchangeDeclare(this.platformExchangeName,
                    this.platformExchangeType,
                    this.plaftormExchangeDurable,
                    this.platformExchangeAutodelete,
                    this.platformExchangeInternal,
                    null);

                startConsumers();

            } catch (IOException e) {
                e.printStackTrace();
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
                channel.queueUnbind(this.loginRequestQueue, this.platformExchangeName,
                    this.loginRequestRoutingKey);
                channel.queueUnbind(this.checkTokenRevocationRequestQueue, this.platformExchangeName,
                    this.checkTokenRevocationRequestRoutingKey);
                channel.queueDelete(this.loginRequestQueue);
                channel.queueDelete(this.checkTokenRevocationRequestQueue);

                closeChannel(channel);
                this.connection.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
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
            e.printStackTrace();
        } finally {
            closeChannel(channel);
        }
    }
}
