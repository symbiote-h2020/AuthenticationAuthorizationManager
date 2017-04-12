package eu.h2020.symbiote.repositories;

import eu.h2020.symbiote.model.TokenModel;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link TokenModel} entities.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface TokenRepository extends MongoRepository<TokenModel, String> {

    TokenModel findByToken(String token);
}
