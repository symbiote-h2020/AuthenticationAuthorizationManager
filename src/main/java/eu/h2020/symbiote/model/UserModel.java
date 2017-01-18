package eu.h2020.symbiote.model;

/**
 * Created by Nemanja on 14.12.2016.
 */

import org.springframework.data.annotation.Id;

import java.util.ArrayList;

import eu.h2020.symbiote.commons.User;

public class UserModel extends User {

    public UserModel() {
        super();
    }

    public UserModel(String username, String password) {
        super(username, password);
    }

    public UserModel(String username, String password, ArrayList<String> attributes) {
        super(username, password, attributes);
    }

    public UserModel(User user) {
        this.setUsername(user.getUsername());
        this.setPassword(user.getPassword());
        this.setAttributes(user.getAttributes());
    }

    @Id
    @Override
    public String getUsername() {
        return super.getUsername();
    }

}
