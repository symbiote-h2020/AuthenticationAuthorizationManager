package eu.h2020.symbiote;

import com.mongodb.Mongo;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
import org.springframework.data.mongodb.core.convert.DbRefResolver;
import org.springframework.data.mongodb.core.convert.DefaultDbRefResolver;
import org.springframework.data.mongodb.core.convert.MappingMongoConverter;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;


/**
 * Used by components with MongoDB
 *
 * @author mateuszl
 * @version 30.09.2016
 */
@Configuration
@EnableMongoRepositories
class AppConfig extends AbstractMongoConfiguration {

    @Override
    protected String getDatabaseName() {
        return "symbiote-core-database";
    }

    @Override
    public Mongo mongo() throws Exception {
        return new Mongo();
    }

    @Override
    protected String getMappingBasePackage() {
        return "com.oreilly.springdata.mongodb";
    }

//    @Bean
//    @Override
//    public MappingMongoConverter mappingMongoConverter() throws Exception
//    {
//        DbRefResolver dbRefResolver = new DefaultDbRefResolver(mongoDbFactory());
//        MappingMongoConverter converter = new MappingMongoConverter(dbRefResolver, mongoMappingContext());
//        converter.setCustomConversions(customConversions());
//        //mongo won't accept key values with dots(.) in them, so configure it to store them as :
//        converter.setMapKeyDotReplacement("\\:");
//
//        return converter;
//    }

}