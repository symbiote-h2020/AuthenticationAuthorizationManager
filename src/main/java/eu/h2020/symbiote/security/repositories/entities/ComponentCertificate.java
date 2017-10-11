package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;
import org.springframework.data.annotation.Id;

/**
 * Class prepared for MongoDB to store component certificates
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class ComponentCertificate {
    @Id
    private final String name;
    private final Certificate certificate;

    /**
     * @param name        e.g. Registry, Search, RAP, etc.
     * @param certificate used in @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    public ComponentCertificate(String name, Certificate certificate) {
        this.name = name;
        this.certificate = certificate;
    }

    /**
     * @return the subject with which the key was associated
     */
    public String getName() {
        return name;
    }

    /**
     * @return the component certificate used in @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    public Certificate getCertificate() {
        return certificate;
    }
}
