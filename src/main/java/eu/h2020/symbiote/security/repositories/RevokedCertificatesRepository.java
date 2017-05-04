package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.certificate.Certificate;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on revoked
 * certificates.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface RevokedCertificatesRepository extends MongoRepository<Certificate, String> {
}