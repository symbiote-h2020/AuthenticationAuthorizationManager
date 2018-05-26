package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
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
    private AccountStatus status = AccountStatus.NEW;
    private String passwordEncrypted = "";
    private String recoveryMail = "";
    private Map<String, Certificate> clientCertificates = new HashMap<>();
    private Set<String> ownedServices = new HashSet<>();

    /**
     * Might be used to assign in registration phase user-unique attributes
     */
    private Map<String, String> attributes = new HashMap<>();

    //GDPR Section
    /**
     * service terms consent is mandatory to provide the service (including suspicious actions identification and blocking)
     */
    private boolean serviceConsent = false;

    /**
     * defines if the user personal data (username, e-mail) and actions can be used for marketing purposes.
     */
    private boolean marketingConsent = false;

    /**
     * Used to create a new user entity
     *
     * @param username           selected username
     * @param passwordEncrypted  encrypted password for authentication
     * @param recoveryMail       for password reset/recovery purposes
     * @param clientCertificates user's public certificates
     * @param role               user's role in symbIoTe ecosystem, see @{@link UserRole}
     * @param status             current status of this account
     * @param attributes         used to assign in registration phase user-unique attributes
     * @param ownedServices      bound to the user
     * @param serviceConsent     service terms consent is mandatory to provide the service (including suspicious actions identification and blocking)
     * @param marketingConsent   defines if the user personal data (username, e-mail) and actions can be used for marketing purposes.
     */
    public User(String username,
                String passwordEncrypted,
                String recoveryMail,
                Map<String, Certificate> clientCertificates,
                UserRole role,
                AccountStatus status,
                Map<String, String> attributes,
                Set<String> ownedServices,
                boolean serviceConsent,
                boolean marketingConsent) {
        this.username = username;
        this.passwordEncrypted = passwordEncrypted;
        this.recoveryMail = recoveryMail;
        this.clientCertificates = clientCertificates;
        this.role = role;
        this.status = status;
        this.attributes = attributes;
        this.ownedServices = ownedServices;
        this.serviceConsent = serviceConsent;
        this.marketingConsent = marketingConsent;
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

    public AccountStatus getStatus() {
        if (this.serviceConsent != true)
            return AccountStatus.CONSENT_BLOCKED;
        return status;
    }

    public void setStatus(AccountStatus status) {
        this.status = status;
    }

    public boolean hasGrantedServiceConsent() {
        return serviceConsent;
    }

    public void setServiceConsent(boolean serviceConsent) {
        this.serviceConsent = serviceConsent;
    }

    public boolean hasGrantedMarketingConsent() {
        return marketingConsent;
    }

    public void setMarketingConsent(boolean marketingConsent) {
        this.marketingConsent = marketingConsent;
    }
}