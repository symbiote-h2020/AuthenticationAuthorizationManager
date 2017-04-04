package eu.h2020.symbiote.commons;

import org.springframework.data.annotation.Id;

import java.util.ArrayList;


/**
 * Class for a standard symbIoTe user, namely an Application.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class Application {

    protected Role role = Role.APPLICATION;

    private String username = "";

    private String passwordEncrypted = "";

    // @DBRef -- might come in useful
    private ArrayList<String> attributes = new ArrayList<>();

    public Application() {
        // required by org.springframework.data.mapping.model.MappingInstantiationException
    }

    public Application(String username, String passwordEncrypted, ArrayList<String> attributes) {
        this.username = username;
        this.passwordEncrypted = passwordEncrypted;
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

    public Role getRole() {
        return role;
    }

}
