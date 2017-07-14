package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on revoked keys.
 *
 * @author Piotr Kicki
 */
public interface RevokedKeysRepository extends MongoRepository<SubjectsRevokedKeys, String> {
}