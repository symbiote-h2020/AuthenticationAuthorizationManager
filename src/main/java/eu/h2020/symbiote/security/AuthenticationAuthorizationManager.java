package eu.h2020.symbiote.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;

import brave.sampler.Sampler;

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

    public static void main(String[] args) {
        SpringApplication.run(AuthenticationAuthorizationManager.class, args);
    }

    @Bean
    public Sampler defaultSampler() {
      return Sampler.ALWAYS_SAMPLE;
    }

}
