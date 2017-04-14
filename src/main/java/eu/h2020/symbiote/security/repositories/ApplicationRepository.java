package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.commons.Application;
import org.springframework.data.mongodb.repository.MongoRepository;


/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link Application} entities.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface ApplicationRepository extends MongoRepository<Application, String> {
}
