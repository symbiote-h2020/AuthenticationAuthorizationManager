package eu.h2020.symbiote.security.config;

import com.google.common.cache.CacheBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CachingConfigurerSupport;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.concurrent.TimeUnit;

/**
 * Used by ValidTokensService
 *
 * @author Jakub Toczek
 */

@Configuration
@EnableCaching
@EnableScheduling
public class CacheConfiguration extends CachingConfigurerSupport {

    private long timeToExpire;
    private long cacheSize;

    public CacheConfiguration(@Value("${aam.cache.expireMillis}") long timeToExpire, @Value("${aam.cache.size}") long cacheSize) {
        this.timeToExpire = timeToExpire;
        this.cacheSize = cacheSize;
    }

    @Override
    public CacheManager cacheManager() {

        return new ConcurrentMapCacheManager() {

            @Override
            protected Cache createConcurrentMapCache(final String name) {
                if (cacheSize == -1) {
                    return new ConcurrentMapCache(name,
                            CacheBuilder.newBuilder().expireAfterWrite(timeToExpire, TimeUnit.MILLISECONDS).build().asMap(), false);
                } else return new ConcurrentMapCache(name,
                        CacheBuilder.newBuilder().expireAfterWrite(timeToExpire, TimeUnit.MILLISECONDS).maximumSize(cacheSize).build().asMap(), false);

            }
        };
    }

}
