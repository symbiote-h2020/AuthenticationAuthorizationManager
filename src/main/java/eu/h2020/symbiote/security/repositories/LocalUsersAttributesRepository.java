package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.Attribute;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on local users attributes used in token issuing.
 *
 * @author Jakub Toczek (PSNC)
 */
public interface LocalUsersAttributesRepository extends MongoRepository<Attribute, String> {
}
