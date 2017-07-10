package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;

import java.util.ArrayList;
import java.util.List;


/**
 * Class for symbIoTe's user entity -- an Application or PlatformOwner
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */

@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class User {

    @Id
    private String username = "";
    private String passwordEncrypted = "";
    private String recoveryMail = "";
    private Certificate certificate = new Certificate();
    // TODO Release 3 - add OAuth federated ID support

    @Indexed
    private UserRole role = UserRole.NULL;

    /**
     * Might be used to assign in registration phase application-unique attributes
     */
    //@DBRef -- might come in useful
    private List<String> attributes = new ArrayList<>();


}
