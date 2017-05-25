package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.token.Token;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on revoked {@link Token} entities.
 *
 * @author Piotr Kicki (PSNC)
 */
public interface RevokedTokensRepository extends MongoRepository<Token, String> {
}
