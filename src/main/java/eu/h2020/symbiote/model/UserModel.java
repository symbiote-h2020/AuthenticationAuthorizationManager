package eu.h2020.symbiote.model;

import java.util.ArrayList;
import org.springframework.data.annotation.Id;
import eu.h2020.symbiote.commons.User;

/**
 * Platform AAM user entity definition for database persistence.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see eu.h2020.symbiote.commons.User
 */
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
