package eu.h2020.symbiote.security.listeners.amqp.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.communication.payloads.LocalUsersAttributesMap;
import eu.h2020.symbiote.security.repositories.LocalUsersAttributesRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.util.Map;

public class LocalUsersAttributesConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(LocalUsersAttributesConsumerService.class);
    private LocalUsersAttributesRepository localUsersAttributesRepository;

    public LocalUsersAttributesConsumerService(Channel channel, LocalUsersAttributesRepository localUsersAttributesRepository) {
        super(channel);
        this.localUsersAttributesRepository = localUsersAttributesRepository;
    }

    /**
     * Called when a <code><b>basic.deliver</b></code> is received for this consumer.
     *
     * @param consumerTag the <i>consumer tag</i> associated with the consumer
     * @param envelope    packaging data for the message
     * @param properties  content header data for the message
     * @param body        the message body (opaque, client-specific byte array)
     * @throws IOException if the consumer encounters an I/O error while processing the message
     * @see Envelope
     */
    @Override
    public void handleDelivery(String consumerTag, Envelope envelope,
                               AMQP.BasicProperties properties, byte[] body)
            throws IOException {

        String message = new String(body, "UTF-8");
        ObjectMapper om = new ObjectMapper();
        LocalUsersAttributesMap map;
        String response;

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            map = om.readValue(message, LocalUsersAttributesMap.class);
            log.debug("[x] Received LocalUsersAttributesMap with: " + map.getAttributes().size() + " attributes");
            localUsersAttributesRepository.deleteAll();
            for (Map.Entry<String, String> entry : map.getAttributes().entrySet()) {
                localUsersAttributesRepository.save(entry.getValue());
            }

            response = "true";
            this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
            log.debug("Revocation Response: sent back");
        } else {
            log.error("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }
}
