package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.enums.UserRole;
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
public class User {

    @Indexed
    private UserRole role = UserRole.NULL;
    @Id
    private String username = "";
    private String passwordEncrypted = "";
    private String recoveryMail = "";
    private Certificate certificate = new Certificate();
    // TODO Release 3 - add OAuth federated ID support

    /**
     * Might be used to assign in registration phase application-unique attributes
     */
    //@DBRef -- might come in useful
    private List<String> attributes = new ArrayList<>();

    public User() {
        // required by org.springframework.data.mapping.model.MappingInstantiationException
    }

    /**
     * Used to create a new user entity
     *
     * @param username          selected username
     * @param passwordEncrypted encrypted password for authentication
     * @param recoveryMail      for password reset/recovery purposes
     * @param certificate       user's public certificate
     * @param role              user's role in symbIoTe ecosystem, see @{@link UserRole}
     * @param attributes        used to assign in registration phase application-unique attributes
     */
    public User(String username, String passwordEncrypted, String recoveryMail, Certificate certificate,
                UserRole role,
                List<String> attributes) {
        this.username = username;
        this.passwordEncrypted = passwordEncrypted;
        this.recoveryMail = recoveryMail;
        this.certificate = certificate;
        this.role = role;
        this.attributes = attributes;
    }

    public UserRole getRole() {
        return role;
    }

    public void setRole(UserRole role) {
        this.role = role;
    }

    @Id
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPasswordEncrypted() {
        return passwordEncrypted;
    }

    public void setPasswordEncrypted(String passwordEncrypted) {
        this.passwordEncrypted = passwordEncrypted;
    }

    public List<String> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<String> attributes) {
        this.attributes = attributes;
    }

    public String getRecoveryMail() {
        return recoveryMail;
    }

    public void setRecoveryMail(String recoveryMail) {
        this.recoveryMail = recoveryMail;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

}
