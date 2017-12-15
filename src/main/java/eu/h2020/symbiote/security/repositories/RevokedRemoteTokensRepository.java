package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.RevokedRemoteToken;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on revoked {@link RevokedRemoteToken} entities.
 *
 * @author Jakub Toczek (PSNC)
 */
public interface RevokedRemoteTokensRepository extends MongoRepository<RevokedRemoteToken, String> {
}
