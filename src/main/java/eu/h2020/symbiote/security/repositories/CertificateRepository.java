package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.commons.Certificate;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on
 * {@link Certificate} entities.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface CertificateRepository extends MongoRepository<Certificate, String> {
}