package eu.h2020.symbiote.security.commons;

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
    private Role role = Role.NULL;
    @Id
    private String username = "";
    private String passwordEncrypted = "";
    private String recoveryMail = "";
    private Certificate certificate = new Certificate();
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
     * @param role              user's role in symbIoTe ecosystem, see @{@link Role}
     * @param attributes        used to assign in registration phase application-unique attributes
     */
    public User(String username, String passwordEncrypted, String recoveryMail, Certificate certificate, Role role,
                List<String> attributes) {
        this.username = username;
        this.passwordEncrypted = passwordEncrypted;
        this.recoveryMail = recoveryMail;
        this.certificate = certificate;
        this.role = role;
        this.attributes = attributes;
    }
    // TODO Release 3 - add OAuth federated ID support

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
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

    /**
     * Denotes what kind of role a user in symbIoTe ecosystem has
     */
    public enum Role {
        /**
         * default symbIoTe's data consumer role
         */
        APPLICATION,
        /**
         * symbIoTe-enabled platform's owner account type, used to release administration attributes
         */
        PLATFORM_OWNER,
        /**
         * unitialized value of this enum
         */
        NULL;
    }
}
