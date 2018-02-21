package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link SmartSpace} entities.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface SmartSpaceRepository extends MongoRepository<SmartSpace, String> {

    /**
     * Used to retrieve smart spaces from repository knowing its Smart Space Owner @{@link User}
     *
     * @param smartSpaceOwner user responsible for this smart space
     * @return @{@link SmartSpace} related with the given user
     */
    SmartSpace findBySmartSpaceOwner(User smartSpaceOwner);
}
