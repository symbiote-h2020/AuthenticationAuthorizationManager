package eu.h2020.symbiote.security.config;

import eu.h2020.symbiote.security.listeners.rest.*;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.springframework.stereotype.Component;

import javax.ws.rs.ApplicationPath;

@Component
@ApplicationPath("/")
public class JerseyConfig extends ResourceConfig {

    public JerseyConfig() {
        register(JacksonFeature.class);
        register(ValidateCredentialsController.class);
        register(GetTokenController.class);
        register(GetClientCertificateController.class);
        register(UserRegistrationController.class);
        register(AAMServices.class);

    }
}