package eu.h2020.symbiote.commons.json;

/**
 * Class that defines the structure of a registration request to CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class RegistrationRequest {
    private LoginRequest AAMOwner;
    private LoginRequest application;

    public RegistrationRequest(LoginRequest AAMOwner, LoginRequest application) {
        this.AAMOwner = AAMOwner;
        this.application = application;
    }

    public RegistrationRequest() {
    }

    public LoginRequest getAAMOwner() {
        return AAMOwner;
    }

    public void setAAMOwner(LoginRequest AAMOwner) {
        this.AAMOwner = AAMOwner;
    }

    public LoginRequest getApplication() {
        return application;
    }

    public void setApplication(LoginRequest application) {
        this.application = application;
    }
}
