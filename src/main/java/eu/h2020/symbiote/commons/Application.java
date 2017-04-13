package eu.h2020.symbiote.commons;

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

    private Role role = Role.NULL;

    private String username = "";

    private String passwordEncrypted = "";

    // @DBRef -- might come in useful
    private ArrayList<String> attributes = new ArrayList<>();

    public Application() {
        // required by org.springframework.data.mapping.model.MappingInstantiationException
    }

    public Application(String username, String passwordEncrypted, ArrayList<String> attributes, Role role) {
        this.username = username;
        this.passwordEncrypted = passwordEncrypted;
        this.attributes = attributes;
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

    public ArrayList<String> getAttributes() {
        return attributes;
    }

    public void setAttributes(ArrayList<String> attributes) {
        this.attributes = attributes;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    /**
     * Created by Mikołaj Dobski on 03.04.2017.
     */
    public enum Role {
        /**
         * specifies platform owner account (administrative user)
         */
        PLATFORM_OWNER,
        /**
         * specifies simple data consumer account (ordinary user)
         */
        APPLICATION,
        /**
         * uninitialised value of this enum
         */
        NULL
    }
}
