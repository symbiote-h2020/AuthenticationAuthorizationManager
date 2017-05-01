package eu.h2020.symbiote.security.commons.json;

/**
 * Class that defines the structure of a plain text credentials payload
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class Credentials {

    private String username = "";
    private String password = "";

    public Credentials(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public Credentials() {
        // empty payload might appear in communication
    }

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


    @Override
    public String toString() {
        return "Credentials [Username=" + username + ", Password=" + password + "]";
    }


}
