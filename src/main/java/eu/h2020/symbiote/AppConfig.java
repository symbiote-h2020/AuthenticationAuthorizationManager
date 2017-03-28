package eu.h2020.symbiote;

import com.mongodb.Mongo;
import com.mongodb.MongoClient;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;


/**
 * Used by components with MongoDB
 *
 * @author mateuszl
 * @author Mikołaj Dobski
 */
@Configuration
@EnableMongoRepositories
class AppConfig extends AbstractMongoConfiguration {

    @Override
    protected String getDatabaseName() {
        return "symbiote-core-aam-database";
    }

    @Override
    public Mongo mongo() throws Exception {
        return new MongoClient();
    }
}