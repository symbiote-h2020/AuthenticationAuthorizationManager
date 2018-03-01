package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.model.mim.Federation;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on Federation entities.
 *
 * @author Jakub Toczek (PSNC)
 */
public interface FederationsRepository extends MongoRepository<Federation, String> {
}
