package eu.h2020.symbiote.repositories;

import org.springframework.data.mongodb.repository.MongoRepository;
import eu.h2020.symbiote.model.TokenModel;

/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link eu.h2020.symbiote.model.TokenModel} entities.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface TokenRepository extends MongoRepository<TokenModel, String>{}
