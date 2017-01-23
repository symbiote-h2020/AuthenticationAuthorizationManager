package eu.h2020.symbiote;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.sleuth.sampler.AlwaysSampler;
import org.springframework.context.annotation.Bean;


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

}
