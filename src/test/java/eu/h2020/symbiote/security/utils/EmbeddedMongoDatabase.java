package eu.h2020.symbiote.security.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.data.mongodb.config.AbstractMongoClientConfiguration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;

import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.IMongodConfig;
import de.flapdoodle.embed.mongo.config.MongodConfigBuilder;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.runtime.Network;

/**
 * Configuration which allows running tests on embedded MongoDB
 *
 * @author Dariusz Krajewski (Intern at PSNC)
 */
@Configuration
@EnableMongoRepositories("eu.h2020.symbiote.security.repositories")
public class EmbeddedMongoDatabase extends AbstractMongoClientConfiguration {
    private static Logger LOG = LoggerFactory.getLogger(EmbeddedMongoDatabase.class);

    @Override
    public String getDatabaseName() {
        return "EmbeddedDataBase";
    }

    public static class EmbeddedMongoDbRunner {
      private static volatile MongodExecutable mongodExecutable;

      public EmbeddedMongoDbRunner(ConfigurableApplicationContext ctx) throws Exception {
        if(mongodExecutable == null) {
          String ip = "localhost";
          int port = 27017;

          int counter = 3;
          while(true) {
            try {
              IMongodConfig mongodConfig = new MongodConfigBuilder().version(Version.Main.PRODUCTION)
                  .net(new Net(ip, port, Network.localhostIsIPv6()))
                  .build();

              MongodStarter starter = MongodStarter.getDefaultInstance();
              mongodExecutable = starter.prepare(mongodConfig);
              mongodExecutable.start();

  //            ctx.addApplicationListener(new ApplicationListener<ContextClosedEvent>() {
  //
  //                @Override
  //                public void onApplicationEvent(ContextClosedEvent event) {
  //                  mongodExecutable.stop();
  //                  mongodExecutable = null;
  //                }
  //            });

              break;
            } catch (Exception e) {
              LOG.info("Waiting for Embeded Mongo to shut down.");
              Thread.sleep(10_000);
              counter--;
              if(counter == 0)
                throw e;
            }
          }
        }
      }
    }

    @Bean
    public EmbeddedMongoDbRunner mongodEmbeddedStarter(ConfigurableApplicationContext ctx) throws Exception {
      return new EmbeddedMongoDbRunner(ctx);
    }

    @Bean @DependsOn({"mongodEmbeddedStarter"})
    @Override
    public MongoClient mongoClient() {
      return MongoClients.create();
    }


}
