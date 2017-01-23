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
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.rabbitmq.consumers.CheckTokenRevocationConsumerService;

/**
 * Configuration class for message queues implementing the Cloud AAM internal interface (defined <a href="http://www.smarteremc2.eu/colab/display/SYM/Platform+AAM%3A+Interface+Definition">here</a>)
 * of the 'check home token revocation' service.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Configuration("tokenRevocationRabbitConfiguration")
public class TokenRevocationRabbitConfiguration {

	private static Log log = LogFactory.getLog(TokenRevocationRabbitConfiguration.class);
	
	/**
	 * 
	 * Exchange and queue initialization for token revocation check from Platform RAP
	 * 
	 */
    @Bean
    @Qualifier(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE)
    Queue checkTokenRevocationRequestPlatformRAPQueue() {
        return new Queue(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE, false);
    }

    @Bean
    @Qualifier(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE)
    Queue checkTokenRevocationReplyPlatformRAPQueue() {
        return new Queue(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE, false);
    }

    @Bean
    @Qualifier(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE)
    //@ConditionalOnMissingBean
    TopicExchange platformAAMPlatformRAPExchange() {
        TopicExchange topicExchange = new TopicExchange("symbIoTe.platformAAM");
        return topicExchange;
    }

    @Bean
    @Qualifier(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE)
    Binding requestCheckTokenRevocationPlatformRAPBinding(@Qualifier(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE) Queue queue,
                           @Qualifier(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE) TopicExchange exchange) {
        return BindingBuilder.bind(queue).to(exchange).with(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_ROUTING_KEY);
    }

    @Bean
    @Qualifier(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE)
    Binding responseCheckTokenRevocationPlatformRAPBinding(@Qualifier(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE) Queue queue,
                            @Qualifier(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE)TopicExchange exchange) {
        return BindingBuilder.bind(queue).to(exchange).with(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_ROUTING_KEY);
    }

    
    
    // The listener container checkTokenRevocationRequestContainer calls the checkTokenRevocationRequestListenerAdapter
    @Bean
    @Qualifier(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE)
    SimpleMessageListenerContainer checkTokenRevocationRequestRegistractionHandlerContainer(ConnectionFactory connectionFactory,
                                                         @Qualifier(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE) MessageListener checkTokenRevocationRequestListenerAdapter) {
        SimpleMessageListenerContainer container = new SimpleMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);
        container.setQueueNames(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE);
        container.setMessageListener(checkTokenRevocationRequestListenerAdapter);
        return container;
    }

    // Request from Registration Handler to checkTokenRevocationRequestListenerAdapter
    @Bean
    @Qualifier(Constants.PLATFORM_AAM_PLATFORM_RAP_CHECK_TOKEN_REVOCATION_REQUEST_QUEUE)
    MessageListener checkTokenRevocationRequestRegistrationHandleListenerAdapter(CheckTokenRevocationConsumerService receiver, ObjectMapper om) {
        return new MessageListener() {
            @Override
            public void onMessage(Message message) {
            	try {
					RequestToken tokenReq = om.readValue(message.getBody(),RequestToken.class);
	                log.info("2. Received AMQP request from Platform RAP: " + new String(message.getBody()));
	                receiver.receiveMessage(tokenReq);
				} catch (IOException e) {
					e.printStackTrace();
				}
            }
        };
    }

	
    // FIXME: 5. The listener container checkTokenRevocationReplyContainer calls the checkTokenRevocationReplyListenerAdapter (REGISTRATION HANDLER SIDE - DEBUG ONLY)
    
    @Bean
    @Qualifier(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE)
    //@ConditionalOnMissingBean
    TopicExchange platformRAPRegistrationHandleExchange() {
        TopicExchange topicExchange = new TopicExchange("symbIoTe.platformRAP");
        return topicExchange;
    }
    
    @Bean
    @Qualifier(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE)
    SimpleMessageListenerContainer checkTokenRevocationReplyPlatformRAPContainer(ConnectionFactory connectionFactory,
                                                       @Qualifier(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE) MessageListener checkTokenRevocationReplyListenerAdapter) {
        SimpleMessageListenerContainer container = new SimpleMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);
        container.setQueueNames(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE);
        container.setMessageListener(checkTokenRevocationReplyListenerAdapter);
        return container;
    }
    
    //  Token revocation Reply from Platform AAM to checkTokenRevocationReplyListenerAdapter (REGISTRATION HANDLER SIDE - DEBUG ONLY)
    @Bean
    @Qualifier(Constants.PLATFORM_RAP_PLATFORM_AAM_CHECK_TOKEN_REVOCATION_REPLY_QUEUE)
    MessageListener checkTokenRevocationReplyPlatformRAPListenerAdapter(CheckTokenRevocationConsumerService receiver, ObjectMapper om) {
        return new MessageListener() {
            @Override
            public void onMessage(Message message) {
                log.info("3. Reply from Platform AAM:" + new String(message.getBody()));
            }
        };
    }
}