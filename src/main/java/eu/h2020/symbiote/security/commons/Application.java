package eu.h2020.symbiote.security.commons;

import org.springframework.data.annotation.Id;

import java.util.ArrayList;


/**
 * Class for symbIoTe's user entity -- an Application or PlatformOwner
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class Application {

    // TODO Release 3 - add OAuth federated ID support
    private String username = "";
    private String passwordEncrypted = "";
    private String recoveryMail = "";
    private Certificate certificate = new Certificate();

    /**
     * @DBRef -- might come in useful
     * might be used to assign in registration phase application-unique attributes
     */
    private ArrayList<String> attributes = new ArrayList<>();

    public Application() {
        // required by org.springframework.data.mapping.model.MappingInstantiationException
    }

    /**
     * Used to create a new application (user) entity
     *
     * @param username          selected username
     * @param passwordEncrypted encrypted password for authentication
     * @param recoveryMail      for password reset/recovery purposes
     * @param certificate
     * @param attributes        used to assign in registration phase application-unique attributes
     */
    public Application(String username, String passwordEncrypted, String recoveryMail, Certificate certificate,
                       ArrayList<String> attributes) {
        this.username = username;
        this.passwordEncrypted = passwordEncrypted;
        this.recoveryMail = recoveryMail;
        this.certificate = certificate;
        this.attributes = attributes;
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

    public ArrayList<String> getAttributes() {
        return attributes;
    }

    public void setAttributes(ArrayList<String> attributes) {
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
