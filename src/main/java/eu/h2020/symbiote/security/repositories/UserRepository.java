package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.User;
import org.springframework.data.mongodb.repository.MongoRepository;


/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link User} entities.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface UserRepository extends MongoRepository<User, String> {
}
