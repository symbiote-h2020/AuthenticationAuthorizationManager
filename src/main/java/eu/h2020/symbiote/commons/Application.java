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
    private String password = "";
    private ArrayList<String> attributes = new ArrayList<String>();

    public Application() {
        // required by org.springframework.data.mapping.model.MappingInstantiationException
    }

    public Application(String username, String password, ArrayList<String> attributes) {
        this.username = username;
        this.password = password;
        this.attributes = attributes;
    }

    public Application(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Id
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
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
