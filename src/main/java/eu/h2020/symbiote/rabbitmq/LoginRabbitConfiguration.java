package eu.h2020.symbiote.rabbitmq;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageListener;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.listener.SimpleMessageListenerContainer;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.rabbitmq.consumers.LoginConsumerService;

/**
 * Configuration class for message queues implementing the Cloud AAM internal interface (defined <a href="http://www.smarteremc2.eu/colab/display/SYM/Platform+AAM%3A+Interface+Definition">here</a>)
 * of the login service.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Configuration("loginRabbitConfiguration")
public class LoginRabbitConfiguration {
	
	private static Log log = LogFactory.getLog(LoginRabbitConfiguration.class);

	/**
	 *
	 * Exchange and queue initialization for login from Registration Handler
	 *
	 */
    @Bean
    @Qualifier(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE)
    Queue loginRequestRegistrationHandlerQueue() {
        return new Queue(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE, false);
    }

    @Bean
    @Qualifier(Constants.REGISTRATION_HANDLER_PLATFORM_AAM_LOGIN_REPLY_QUEUE)
    Queue loginReplyRegistrationHandlerQueue() {
        return new Queue(Constants.REGISTRATION_HANDLER_PLATFORM_AAM_LOGIN_REPLY_QUEUE, false);
    }

    @Bean
    @Qualifier(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE)
    //@ConditionalOnMissingBean
    TopicExchange platformAAMRegistrationHandlerExchange() {
        TopicExchange topicExchange = new TopicExchange("symbIoTe.platformAAM");
        return topicExchange;
    }

    @Bean
    @Qualifier(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE)
    Binding requestLoginRegistrationHandlerBinding(@Qualifier(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE) Queue queue,
                           @Qualifier(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE) TopicExchange exchange) {
        return BindingBuilder.bind(queue).to(exchange).with(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_ROUTING_KEY);
    }

    @Bean
    @Qualifier(Constants.REGISTRATION_HANDLER_PLATFORM_AAM_LOGIN_REPLY_QUEUE)
    Binding responseLoginRegistrationHandlerBinding(@Qualifier(Constants.REGISTRATION_HANDLER_PLATFORM_AAM_LOGIN_REPLY_QUEUE) Queue queue,
                            @Qualifier(Constants.REGISTRATION_HANDLER_PLATFORM_AAM_LOGIN_REPLY_QUEUE)TopicExchange exchange) {
        return BindingBuilder.bind(queue).to(exchange).with(Constants.REGISTRATION_HANDLER_PLATFORM_AAM_LOGIN_REPLY_ROUTING_KEY);
    }

    
    
    // The listener container loginRequestContainer calls the loginRequestListenerAdapter
    @Bean
    @Qualifier(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE)
    SimpleMessageListenerContainer loginRequestRegistractionHandlerContainer(ConnectionFactory connectionFactory,
                                                         @Qualifier(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE) MessageListener loginRequestListenerAdapter) {
        SimpleMessageListenerContainer container = new SimpleMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);
        container.setQueueNames(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE);
        container.setMessageListener(loginRequestListenerAdapter);
        return container;
    }

    // Request from Registration Handler to loginRequestListenerAdapter
    @Bean
    @Qualifier(Constants.PLATFORM_AAM_REGISTRATION_HANDLER_LOGIN_REQUEST_QUEUE)
    MessageListener loginRequestRegistrationHandleListenerAdapter(LoginConsumerService receiver, ObjectMapper om) {
        return new MessageListener() {
            @Override
            public void onMessage(Message message) {
            	try {
					LoginRequest loginReq = om.readValue(message.getBody(),LoginRequest.class);
	                log.info("2. Received Login AMQP request from Registration Handler: " + new String(message.getBody()));
	                receiver.receiveMessage(loginReq);
				} catch (IOException e) {
					e.printStackTrace();
				}
            }
        };
    }

	/**
	 * 
	 * Exchange and queue initialization for login from Monitoring
	 * 
	 */
    @Bean
    @Qualifier(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE)
    Queue loginRequestMonitoringQueue() {
        return new Queue(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE, false);
    }

    @Bean
    @Qualifier(Constants.MONITORING_PLATFORM_AAM_LOGIN_REPLY_QUEUE)
    Queue loginReplyMonitoringQueue() {
        return new Queue(Constants.MONITORING_PLATFORM_AAM_LOGIN_REPLY_QUEUE, false);
    }

    @Bean
    @Qualifier(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE)
    //@ConditionalOnMissingBean
    TopicExchange platformAAMMonitoringExchange() {
        TopicExchange topicExchange = new TopicExchange("symbIoTe.platformAAM");
        return topicExchange;
    }

    @Bean
    @Qualifier(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE)
    Binding requestLoginMonitoringBinding(@Qualifier(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE) Queue queue,
                           @Qualifier(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE) TopicExchange exchange) {
        return BindingBuilder.bind(queue).to(exchange).with(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_ROUTING_KEY);
    }

    @Bean
    @Qualifier(Constants.MONITORING_PLATFORM_AAM_LOGIN_REPLY_QUEUE)
    Binding responseLoginMonitoringBinding(@Qualifier(Constants.MONITORING_PLATFORM_AAM_LOGIN_REPLY_QUEUE) Queue queue,
                            @Qualifier(Constants.MONITORING_PLATFORM_AAM_LOGIN_REPLY_QUEUE)TopicExchange exchange) {
        return BindingBuilder.bind(queue).to(exchange).with(Constants.MONITORING_PLATFORM_AAM_LOGIN_REPLY_ROUTING_KEY);
    }

    
    
    // The listener container loginRequestContainer calls the loginRequestListenerAdapter
    @Bean
    @Qualifier(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE)
    SimpleMessageListenerContainer loginRequestMonitoringContainer(ConnectionFactory connectionFactory,
                                                         @Qualifier(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE) MessageListener loginRequestListenerAdapter) {
        SimpleMessageListenerContainer container = new SimpleMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);
        container.setQueueNames(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE);
        container.setMessageListener(loginRequestListenerAdapter);
        return container;
    }

    // Request from Registration Handler to loginRequestListenerAdapter
    @Bean
    @Qualifier(Constants.PLATFORM_AAM_MONITORING_LOGIN_REQUEST_QUEUE)
    MessageListener loginRequestMonitoringListenerAdapter(LoginConsumerService receiver, ObjectMapper om) {
        return new MessageListener() {
            @Override
            public void onMessage(Message message) {
            	try {
					LoginRequest loginReq = om.readValue(message.getBody(),LoginRequest.class);
	                log.info("2. Received Login AMQP request from Monitoring: " + new String(message.getBody()));
	                receiver.receiveMessage(loginReq);
				} catch (IOException e) {
					e.printStackTrace();
				}
            }
        };
    }
}