package eu.h2020.symbiote.commons;

import java.util.ArrayList;

/**
 * Created by Mikołaj on 03.04.2017.
 */
public class PlatformOwner extends Application {


    public PlatformOwner(String username, String password, ArrayList<String> attributes) {
        super(username, password, attributes);
        role = Role.PLATFORM_OWNER;
    }
}
