package eu.h2020.symbiote.commons.json;

/**
 * Class that defines the structure of a registration request to CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class RegistrationRequest {
    private LoginRequest platformOwner;
    private LoginRequest application;

    public RegistrationRequest(LoginRequest platformOwner, LoginRequest application) {
        this.platformOwner = platformOwner;
        this.application = application;
    }

    public RegistrationRequest() {
    }

    public LoginRequest getPlatformOwner() {
        return platformOwner;
    }

    public void setPlatformOwner(LoginRequest platformOwner) {
        this.platformOwner = platformOwner;
    }

    public LoginRequest getApplication() {
        return application;
    }

    public void setApplication(LoginRequest application) {
        this.application = application;
    }
}
