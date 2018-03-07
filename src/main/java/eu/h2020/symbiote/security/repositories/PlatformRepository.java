package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Set;

/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link Platform} entities.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public interface PlatformRepository extends MongoRepository<Platform, String> {

    /**
     * Used to retrieve platform from repository knowing its PlatformOwner @{@link User}
     *
     * @param platformOwner user responsible for this platform
     * @return @{@link Platform} related with the given user
     */
    Set<Platform> findByPlatformOwner(User platformOwner);
}
