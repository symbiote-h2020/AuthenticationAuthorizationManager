package eu.h2020.symbiote.security.utils;

import com.github.fakemongo.Fongo;
import com.mongodb.Mongo;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

/**
 * Created by Dariusz Krajewski on 12/07/17.
 */

@Configuration
@EnableMongoRepositories("eu.h2020.symbiote.security.repositories")
public class EmbeddedFongoDB extends AbstractMongoConfiguration {
    @Override
    public String getDatabaseName() {
        return "Placeholder";
    }

    @Bean
    @Override
    public Mongo mongo() {
        return new Fongo("placeholder").getMongo();
    }

}
