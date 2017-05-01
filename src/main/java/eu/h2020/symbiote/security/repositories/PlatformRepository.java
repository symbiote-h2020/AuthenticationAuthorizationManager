package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.commons.Platform;
import eu.h2020.symbiote.security.commons.User;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link Platform} entities.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public interface PlatformRepository extends MongoRepository<Platform, String> {

    /**
     * Used to retrieve platform from repository knowing it's PlatformOwner @{@link User}
     * @param platformOwner user responsible for this platform
     * @return @{@link Platform} related with the given user
     */
    Platform findByPlatformOwner(User platformOwner);
}
