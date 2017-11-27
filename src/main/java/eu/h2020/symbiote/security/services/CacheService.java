package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Token;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

/**
 * Spring service used for caching.
 * <p>
 *
 * @author Jakub Toczek (PSNC)
 */
@Service
public class CacheService {

    @CachePut(cacheNames = "validTokens", key = "#token.getClaims().getIssuer() + '@' + #token.id")
    public boolean cacheValidToken(Token token) {
        return true;
    }

    @Cacheable(cacheNames = "validTokens", key = "#token.getClaims().getIssuer()+ '@' +#token.id")
    public boolean isValidTokenCached(Token token) {
        // we assume that the cache is already populated
        return false;
    }

}
