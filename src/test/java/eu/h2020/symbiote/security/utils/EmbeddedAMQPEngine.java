package eu.h2020.symbiote.security.utils;

import io.arivera.oss.embedded.rabbitmq.EmbeddedRabbitMq;
import io.arivera.oss.embedded.rabbitmq.EmbeddedRabbitMqConfig;
import io.arivera.oss.embedded.rabbitmq.PredefinedVersion;
import io.arivera.oss.embedded.rabbitmq.RabbitMqEnvVar;
import org.apache.commons.lang.SystemUtils;
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
    private EmbeddedRabbitMq embeddedRabbitMq;
    private String extractionPath;

    public EmbeddedAMQPEngine() {
        EmbeddedRabbitMqConfig.Builder embeddedRabbitMqConfigBuilder = new EmbeddedRabbitMqConfig.Builder()
                .version(PredefinedVersion.LATEST)
                .rabbitMqServerInitializationTimeoutInMillis(60000);//1 minute
        if (SystemUtils.IS_OS_WINDOWS && pathContainsInvalidChar()) {
            avoidInvalidChar();
            embeddedRabbitMqConfigBuilder.extractionFolder(new File(extractionPath))
                    .envVar(RabbitMqEnvVar.CONF_ENV_FILE, "C:/Temp/rabbitTemp");
        }
        embeddedRabbitMq = new EmbeddedRabbitMq(embeddedRabbitMqConfigBuilder.build());
        embeddedRabbitMq.start();
    }

    /*
     *  Issue valid extraction path
     */
    public void avoidInvalidChar() {
        String workaroundPath = "C:/Temp/rabbitTemp";
        Path tempPath = Paths.get(workaroundPath);
        if (Files.exists(tempPath)) {
            // Success - Path exists, select it for extraction
            extractionPath = workaroundPath;
        } else {
            // Fail - Path does not exist - needs creation
            throw new UnsupportedOperationException("User Home Path contains illegal characters. Please create "
                    + "new directory " + workaroundPath);
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
