package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.commons.TokenEntity;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link TokenEntity} entities.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface TokenRepository extends MongoRepository<TokenEntity, String> {

    TokenEntity findByToken(String token);
}
