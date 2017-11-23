package eu.h2020.symbiote.security.config;

import com.mongodb.Mongo;
import com.mongodb.MongoClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


/**
 * Used by components with MongoDB
 *
 * @author mateuszl
 * @author Mikołaj Dobski
 */
@Configuration
@EnableCaching
@EnableMongoRepositories("eu.h2020.symbiote.security.repositories")
class AppConfig extends AbstractMongoConfiguration {

    private final Object syncObject = new Object();
    private String databaseName;
    private MongoClient mongoClient = null;

    AppConfig(@Value("${aam.database.name}") String databaseName) {
        this.databaseName = databaseName;
    }

    @Override
    protected String getDatabaseName() {
        return databaseName;
    }

    @Override
    public Mongo mongo() throws Exception {
        synchronized (syncObject) {
            if (mongoClient == null) {
                mongoClient = new MongoClient();
            }
        }
        return mongoClient;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}