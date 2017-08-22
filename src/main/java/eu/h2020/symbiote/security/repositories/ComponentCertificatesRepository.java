package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import org.springframework.data.mongodb.repository.MongoRepository;


/**
 * Spring repository interface definition to be used with MongoDB for operations on SymbIoTe Core components' certificates
 *
 * @author Mikołaj Dobski (PSNC)
 */
public interface ComponentCertificatesRepository extends MongoRepository<ComponentCertificate, String> {
}
