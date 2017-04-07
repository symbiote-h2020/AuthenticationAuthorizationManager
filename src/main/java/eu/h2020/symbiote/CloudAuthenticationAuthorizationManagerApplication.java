package eu.h2020.symbiote;

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
import eu.h2020.symbiote.rabbitmq.RabbitManager;

/**
 * Spring Boot Application class for Cloud Authentication and Authorization Manager (Cloud AAM) component.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@EnableDiscoveryClient
@SpringBootApplication
public class CloudAuthenticationAuthorizationManagerApplication {

	private static Log log = LogFactory.getLog(CloudAuthenticationAuthorizationManagerApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(CloudAuthenticationAuthorizationManagerApplication.class, args);

        try {
            // Subscribe to RabbitMQ messages
        } catch (Exception e) {
            log.error("Error occured during subscribing from Cloud Authentication Authorization Manager", e);
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
