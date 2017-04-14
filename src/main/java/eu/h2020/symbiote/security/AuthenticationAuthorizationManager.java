package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.amqp.RabbitManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.sleuth.sampler.AlwaysSampler;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

/**
 * Spring Boot Application class for AuthenticationAuthorizationManager (AAM) component.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikolaj Dobski (PSNC)
 */
@EnableDiscoveryClient
@SpringBootApplication(scanBasePackages = "eu.h2020.symbiote.security")
public class AuthenticationAuthorizationManager {

    private static Log log = LogFactory.getLog(AuthenticationAuthorizationManager.class);

    public static void main(String[] args) {
        SpringApplication.run(AuthenticationAuthorizationManager.class, args);

        try {
            // todo: Subscribe to RabbitMQ messages
        } catch (Exception e) {
            log.error("Error occurred during subscribing from  Authentication Authorization Manager", e);
        }
    }

    @Bean
    public AlwaysSampler defaultSampler() {
        return new AlwaysSampler();
    }


    @Component
    public static class CLR implements CommandLineRunner {

        private final RabbitManager rabbitManager;

        @Autowired
        public CLR(RabbitManager rabbitManager) {
            this.rabbitManager = rabbitManager;
        }

        @Override
        public void run(String... args) throws Exception {
//
            //message retrieval - start rabbit exchange and consumers
            this.rabbitManager.init();
            log.info("CLR run() and Rabbit Manager init()");
        }
    }

}
