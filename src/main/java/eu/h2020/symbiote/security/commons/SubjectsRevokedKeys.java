package eu.h2020.symbiote.security.commons;

import org.springframework.data.annotation.Id;

import java.util.List;

/**
 * Class prepared for MongoDB to store revoked keys
 *
 * @author Piotr Kicki (PSNC)
 */
public class SubjectsRevokedKeys {
    @Id
    private String subjectId;
    private List<String> list;

    public SubjectsRevokedKeys() {
        // required by org.springframework.data.mapping.model.MappingInstantiationException
    }

    public SubjectsRevokedKeys(String subjectId, List<String> list) {
        this.subjectId = subjectId;
        this.list = list;
    }
}
