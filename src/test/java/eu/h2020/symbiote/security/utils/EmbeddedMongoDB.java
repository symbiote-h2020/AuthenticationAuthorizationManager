package eu.h2020.symbiote.security.utils;

import com.github.fakemongo.Fongo;
import com.mongodb.Mongo;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

/**
 * Configuration which allows running tests on embedded MongoDB
 *
 * @author Dariusz Krajewski (Intern at PSNC)
 */
@Configuration
@EnableMongoRepositories("eu.h2020.symbiote.security.repositories")
public class EmbeddedMongoDB extends AbstractMongoConfiguration {
    @Override
    public String getDatabaseName() {
        return "EmbeddedDataBase";
    }

    @Bean
    @Override
    public Mongo mongo() {
        return new Fongo("MongoDatabase").getMongo();
    }
}
