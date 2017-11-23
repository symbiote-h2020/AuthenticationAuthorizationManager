package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Token;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

/**
 * Spring service used to cache valid tokens.
 * <p>
 *
 * @author Jakub Toczek (PSNC)
 */
@Service
public class ValidTokensService {

    @CachePut(cacheNames = "validTokens", key = "#token.getClaims().getIssuer() + #token.id")
    public boolean save(Token token) {
        return true;
    }

    @Cacheable(cacheNames = "validTokens", key = "#token.getClaims().getIssuer() + #token.id")
    public boolean exists(Token token) {
        // we assume that the cache is already populated
        return false;
    }

}
