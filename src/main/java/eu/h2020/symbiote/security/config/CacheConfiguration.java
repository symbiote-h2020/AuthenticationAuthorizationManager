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

    private long validTokenTimeToExpire;
    private long validTokenCacheSize;
    private long componentCertificateTimeToExpire;
    private long availableAAMsTimeToExpire;

    public CacheConfiguration(@Value("${aam.cache.validToken.expireMillis:60000}") long validTokenTimeToExpire,
                              @Value("${aam.cache.validToken.size:1000}") long validTokenCacheSize,
                              @Value("${aam.cache.componentCertificate.expireSeconds:60}") long componentCertificateTimeToExpire,
                              @Value("${aam.cache.availableAAMs.expireSeconds:60}") long availableAAMsTimeToExpire) {
        this.validTokenTimeToExpire = validTokenTimeToExpire;
        this.validTokenCacheSize = validTokenCacheSize;
        this.componentCertificateTimeToExpire = componentCertificateTimeToExpire;
        this.availableAAMsTimeToExpire = availableAAMsTimeToExpire;
    }

    @Override
    public CacheManager cacheManager() {

        return new ConcurrentMapCacheManager() {

            @Override
            protected Cache createConcurrentMapCache(final String name) {
                switch (name) {
                    case "getComponentCertificate":
                        return new ConcurrentMapCache(name,
                                CacheBuilder.newBuilder().expireAfterWrite(componentCertificateTimeToExpire, TimeUnit.SECONDS).build().asMap(), false);
                    case "getAvailableAAMs":
                        return new ConcurrentMapCache(name,
                                CacheBuilder.newBuilder().expireAfterWrite(availableAAMsTimeToExpire, TimeUnit.SECONDS).build().asMap(), false);
                    case "validTokens":
                        if (validTokenCacheSize == -1) {
                            return new ConcurrentMapCache(name,
                                    CacheBuilder.newBuilder().expireAfterWrite(validTokenTimeToExpire, TimeUnit.MILLISECONDS).build().asMap(), false);
                        } else return new ConcurrentMapCache(name,
                                CacheBuilder.newBuilder().expireAfterWrite(validTokenTimeToExpire, TimeUnit.MILLISECONDS).maximumSize(validTokenCacheSize).build().asMap(), false);
                    default:
                        throw new SecurityException("There is no configuration for cache named: " + name);
                }
            }
        };
    }

}
