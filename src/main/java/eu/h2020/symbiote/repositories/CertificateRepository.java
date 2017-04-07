package eu.h2020.symbiote.repositories;

import org.springframework.data.mongodb.repository.MongoRepository;
import eu.h2020.symbiote.model.CertificateModel;

/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link eu.h2020.symbiote.model.CertificateModel} entities.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface CertificateRepository extends MongoRepository<CertificateModel, String> {}