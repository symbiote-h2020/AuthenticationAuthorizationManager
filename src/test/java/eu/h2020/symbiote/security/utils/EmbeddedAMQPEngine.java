package eu.h2020.symbiote.security.utils;

import io.arivera.oss.embedded.rabbitmq.EmbeddedRabbitMq;
import io.arivera.oss.embedded.rabbitmq.EmbeddedRabbitMqConfig;
import io.arivera.oss.embedded.rabbitmq.PredefinedVersion;
import org.apache.commons.lang.SystemUtils;
import org.assertj.core.api.exception.RuntimeIOException;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.Normalizer;

/**
 * Component which allows running tests using Embedded AMQP Engine
 *
 * @author Dariusz Krajewski (PSNC)
 */
@Component
public class EmbeddedAMQPEngine {
    private EmbeddedRabbitMqConfig embeddedRabbitMqConfig;
    private EmbeddedRabbitMq embeddedRabbitMq;
    private String extractionPath;

    public EmbeddedAMQPEngine() {
        if (SystemUtils.IS_OS_WINDOWS && pathContainsInvalidChar()) {
            avoidInvalidChar();
            embeddedRabbitMqConfig = new EmbeddedRabbitMqConfig.Builder()
                    .version(PredefinedVersion.LATEST)
                    .extractionFolder(new File(extractionPath + "/rabbitTemps"))
                    .build();
        } else {
            embeddedRabbitMqConfig = new EmbeddedRabbitMqConfig.Builder()
                    .version(PredefinedVersion.LATEST)
                    .build();
        }

        embeddedRabbitMq = new EmbeddedRabbitMq(embeddedRabbitMqConfig);
        embeddedRabbitMq.start();
    }

    /*
     *  Issue valid extracion path
     */
    public void avoidInvalidChar() {
        Path tempPath = Paths.get(System.getProperty("java.io.tmpdir") + "/rabbitTemps");
        if (Files.exists(tempPath)) {
            //  Success - Path exists, select it for extraction
            extractionPath = System.getProperty("java.io.tmpdir");
        } else {
            //  Fail - Path does not exist - needs creation
            throw new RuntimeIOException("User Home Path contains illegal characters. Please create " +
                    "new directory in C:/Temp/rabbitTemps");
        }
    }

    /*
     *  Verify that User Home path doesn't contain diacritics or illegal characters
     */
    public boolean pathContainsInvalidChar() {
        CharSequence homePath = System.getProperty("user.home");
        return Normalizer.isNormalized(homePath, Normalizer.Form.NFD);
    }

    @PreDestroy
    public void cleanup() {
        embeddedRabbitMq.stop();
    }
}
