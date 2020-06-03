package eu.h2020.symbiote.security;

import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.SimpleMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitTestConfiguration {
  @Bean
  public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
      RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
      rabbitTemplate.setMessageConverter(simpleMessageConverter());
      return rabbitTemplate;
  }

  @Bean
  public SimpleMessageConverter simpleMessageConverter() {
      return new SimpleMessageConverter();
  }
}
