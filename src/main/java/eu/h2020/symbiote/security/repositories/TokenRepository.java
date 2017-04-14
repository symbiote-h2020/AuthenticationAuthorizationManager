package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.commons.Token;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link Token} entities.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface TokenRepository extends MongoRepository<Token, String> {

    Token findByToken(String token);
}
