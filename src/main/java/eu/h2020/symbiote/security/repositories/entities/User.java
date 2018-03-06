package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


/**
 * Class for symbIoTe's user entity -- an Application or PlatformOwner
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class User {

    @Id
    private final String username;
    @Indexed
    private UserRole role = UserRole.NULL;
    private String passwordEncrypted = "";
    private String recoveryMail = "";
    private Map<String, Certificate> clientCertificates = new HashMap<>();
    private Set<String> ownedServices = new HashSet<>();

    /**
     * Might be used to assign in registration phase user-unique attributes
     */
    private Map<String, String> attributes = new HashMap<>();

    /**
     * Used to create a new user entity
     *
     * @param username           selected username
     * @param passwordEncrypted  encrypted password for authentication
     * @param recoveryMail       for password reset/recovery purposes
     * @param clientCertificates user's public certificates
     * @param role               user's role in symbIoTe ecosystem, see @{@link UserRole}
     * @param attributes         used to assign in registration phase user-unique attributes
     * @param ownedServices      bound to the user
     */
    public User(String username,
                String passwordEncrypted,
                String recoveryMail,
                Map<String, Certificate> clientCertificates,
                UserRole role,
                Map<String, String> attributes,
                Set<String> ownedServices) {
        this.username = username;
        this.passwordEncrypted = passwordEncrypted;
        this.recoveryMail = recoveryMail;
        this.clientCertificates = clientCertificates;
        this.role = role;
        this.attributes = attributes;
        this.ownedServices = ownedServices;
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

    public Set<String> getOwnedServices() {
        return ownedServices;
    }

    public void setOwnedServices(Set<String> ownedServices) {
        this.ownedServices = ownedServices;
    }
}