package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.BlockedAction;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface BlockedActionsRepository extends MongoRepository<BlockedAction, String> {

    /**
     * Used to find repository entries for specific user.
     *
     * @param username user
     * @return true/false
     */
    List<BlockedAction> findByUsername(String username);
}
