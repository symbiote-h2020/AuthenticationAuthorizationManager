package eu.h2020.symbiote.security.commons;

import org.springframework.data.annotation.Id;

import java.util.Set;

/**
 * Class prepared for MongoDB to store revoked keys
 *
 * @author Piotr Kicki (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class SubjectsRevokedKeys {
    @Id
    private String subjectId;
    private Set<String> revokedKeysSet;

    public SubjectsRevokedKeys() {
        // required by org.springframework.data.mapping.model.MappingInstantiationException
    }

    public SubjectsRevokedKeys(String subjectId, Set<String> revokedKeysSet) {
        this.subjectId = subjectId;
        this.revokedKeysSet = revokedKeysSet;
    }

    /**
     * @return the subject with which the key was associated
     */
    public String getSubjectId() {
        return subjectId;
    }

    public void setSubjectId(String subjectId) {
        this.subjectId = subjectId;
    }

    /**
     * @return collection of revoked public keys strings for the associated subject
     */
    public Set<String> getRevokedKeysSet() {
        return revokedKeysSet;
    }

    public void setRevokedKeysSet(Set<String> revokedKeysSet) {
        this.revokedKeysSet = revokedKeysSet;
    }
}
