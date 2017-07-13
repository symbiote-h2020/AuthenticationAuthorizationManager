package eu.h2020.symbiote.security.utils;

import io.arivera.oss.embedded.rabbitmq.EmbeddedRabbitMq;
import io.arivera.oss.embedded.rabbitmq.EmbeddedRabbitMqConfig;
import io.arivera.oss.embedded.rabbitmq.PredefinedVersion;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;

/**
 * Component which allows running tests using Embedded AMQP Engine
 *
 * @author Dariusz Krajewski (PSNC)
 */
@Component
public class EmbeddedAMQPEngine {
    private EmbeddedRabbitMqConfig embeddedRabbitMqConfig;
    private EmbeddedRabbitMq embeddedRabbitMq;

    public EmbeddedAMQPEngine() {
        embeddedRabbitMqConfig = new EmbeddedRabbitMqConfig.Builder()
                .version(PredefinedVersion.LATEST)
                .build();
        embeddedRabbitMq = new EmbeddedRabbitMq(embeddedRabbitMqConfig);
        embeddedRabbitMq.start();
    }

    @PreDestroy
    public void cleanup() {
        embeddedRabbitMq.stop();
    }
}
