package eu.h2020.symbiote.security.commons;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;

import java.util.Set;

/**
 * Class prepared for MongoDB to store revoked keys
 *
 * @author Piotr Kicki (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Getter @Setter @AllArgsConstructor @NoArgsConstructor
public class SubjectsRevokedKeys {
    @Id
    private String subjectId;
    private Set<String> revokedKeysSet;
}
