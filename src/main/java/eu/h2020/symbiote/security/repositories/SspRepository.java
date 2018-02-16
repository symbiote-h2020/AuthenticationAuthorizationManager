package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.Ssp;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link Ssp} entities.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface SspRepository extends MongoRepository<Ssp, String> {

    /**
     * Used to retrieve ssp from repository knowing its SspOwner @{@link User}
     *
     * @param sspOwner user responsible for this ssp
     * @return @{@link Ssp} related with the given user
     */
    Ssp findBySspOwner(User sspOwner);
}
