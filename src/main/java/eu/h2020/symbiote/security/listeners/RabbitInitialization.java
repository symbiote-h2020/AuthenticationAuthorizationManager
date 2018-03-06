package eu.h2020.symbiote.security.listeners;

import org.springframework.amqp.rabbit.config.SimpleRabbitListenerContainerFactory;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.support.converter.SimpleMessageConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Profile({"core", "platform"})
@Component
public class RabbitInitialization {

    private final String rabbitHost;
    private final String rabbitUsername;
    private final String rabbitPassword;

    public RabbitInitialization(@Value("${rabbit.host}") String rabbitHost,
                                @Value("${rabbit.username}") String rabbitUsername,
                                @Value("${rabbit.password}") String rabbitPassword) {
        this.rabbitHost = rabbitHost;
        this.rabbitUsername = rabbitUsername;
        this.rabbitPassword = rabbitPassword;
    }

    @Bean
    public SimpleRabbitListenerContainerFactory rabbitListenerContainerFactory(ConnectionFactory connectionFactory) {
        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
        factory.setConnectionFactory(connectionFactory);
        factory.setMessageConverter(simpleMessageConverter());
        return factory;
    }

    @Bean
    SimpleMessageConverter simpleMessageConverter() {
        return new SimpleMessageConverter();
    }

    @Bean
    public ConnectionFactory connectionFactory() {
        CachingConnectionFactory connectionFactory = new CachingConnectionFactory(rabbitHost);
        connectionFactory.setUsername(rabbitUsername);
        connectionFactory.setPassword(rabbitPassword);
        return connectionFactory;
    }
}
