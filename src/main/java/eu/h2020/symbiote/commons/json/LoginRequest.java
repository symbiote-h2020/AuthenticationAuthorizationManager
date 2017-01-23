package eu.h2020.symbiote.commons.json;

import java.util.ArrayList;


/**
 * Class that defines the structure of a login request to CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class LoginRequest {
    private String username;
    private String password;
    private ArrayList<String> attributes;

    public LoginRequest() {
        this.username = null;
        this.password = null;
        this.attributes = null;
    }

    public LoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
        this.attributes = null;
    }

    public LoginRequest(String username, String password, ArrayList<String> attributes) {
        this.username = username;
        this.password = password;
        this.attributes = attributes;
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

    public ArrayList<String> getAttributes() {
        return attributes;
    }

    public void setAttributes(ArrayList<String> attributes) {
        this.attributes = attributes;
    }

	@Override
	public String toString() {
		return "LoginRequest [username=" + username + ", password=" + password + ", attributes=" + attributes + "]";
	}
    
    
}
