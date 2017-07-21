package eu.h2020.symbiote.security.config;

import eu.h2020.symbiote.security.listeners.rest.AAMServices;
import eu.h2020.symbiote.security.listeners.rest.ValidateCredentialsController;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.springframework.stereotype.Component;

@Component
public class JerseyConfig extends ResourceConfig {

    public JerseyConfig() {
        register(JacksonFeature.class);
        register(AAMServices.class);
        register(ValidateCredentialsController.class);
    }

}