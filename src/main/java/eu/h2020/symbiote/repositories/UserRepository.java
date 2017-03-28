package eu.h2020.symbiote.repositories;

import eu.h2020.symbiote.model.UserModel;
import org.springframework.data.mongodb.repository.MongoRepository;


/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link UserModel} entities.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface UserRepository extends MongoRepository<UserModel, String>{}
