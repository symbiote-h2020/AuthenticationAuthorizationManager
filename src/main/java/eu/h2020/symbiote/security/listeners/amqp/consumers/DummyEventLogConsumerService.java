package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;


public class DummyEventLogConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(OwnedPlatformDetailsRequestConsumerService.class);

    public DummyEventLogConsumerService(Channel channel) {
        super(channel);
    }

    @Override
    public void handleDelivery(String consumerTag, Envelope envelope,
                               AMQP.BasicProperties properties, byte[] body)
            throws IOException {

        String message = new String(body, "UTF-8");
        log.info("[x] Received Event Log Request " + message);

        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}