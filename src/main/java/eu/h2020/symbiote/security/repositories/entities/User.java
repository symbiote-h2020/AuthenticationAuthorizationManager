package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DBRef;

import java.util.HashMap;
import java.util.Map;


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
    private Map<String, Certificate> clientCertificates = new HashMap<>();

    @DBRef(lazy = true)
    private Map<String, Platform> ownedPlatforms = new HashMap<>();

    // TODO Release 4 - add OAuth federated ID support

    /**
     * Might be used to assign in registration phase user-unique attributes
     */
    //@DBRef -- might come in useful
    private Map<String, String> attributes = new HashMap<>();

    public User() {
        // required by org.springframework.data.mapping.model.MappingInstantiationException
    }

    /**
     * Used to create a new user entity
     *
     * @param username           selected username
     * @param passwordEncrypted  encrypted password for authentication
     * @param recoveryMail       for password reset/recovery purposes
     * @param clientCertificates user's public certificates
     * @param role               user's role in symbIoTe ecosystem, see @{@link UserRole}
     * @param attributes         used to assign in registration phase user-unique attributes
     */
    public User(String username, String passwordEncrypted, String recoveryMail, Map<String, Certificate> clientCertificates,
                UserRole role,
                Map<String, String> attributes) {
        this.username = username;
        this.passwordEncrypted = passwordEncrypted;
        this.recoveryMail = recoveryMail;
        this.clientCertificates = clientCertificates;
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

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    public String getRecoveryMail() {
        return recoveryMail;
    }

    public void setRecoveryMail(String recoveryMail) {
        this.recoveryMail = recoveryMail;
    }

    public Map<String, Certificate> getClientCertificates() {
        return clientCertificates;
    }

    public void setClientCertificates(Map<String, Certificate> clientCertificates) {
        this.clientCertificates = clientCertificates;
    }

    public Map<String, Platform> getOwnedPlatforms() {
        return ownedPlatforms;
    }

    public void setOwnedPlatforms(Map<String, Platform> ownedPlatforms) {
        this.ownedPlatforms = ownedPlatforms;
    }
}