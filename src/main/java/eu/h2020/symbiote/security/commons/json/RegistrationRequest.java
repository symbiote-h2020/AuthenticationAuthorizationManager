package eu.h2020.symbiote.security.commons.json;

/**
 * Class that defines the structure of a registration request to AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class RegistrationRequest {
    private PlainCredentials AAMOwner;
    private PlainCredentials application;

    public RegistrationRequest(PlainCredentials AAMOwner, PlainCredentials application) {
        this.AAMOwner = AAMOwner;
        this.application = application;
    }

    public RegistrationRequest() {
    }

    public PlainCredentials getAAMOwner() {
        return AAMOwner;
    }

    public void setAAMOwner(PlainCredentials AAMOwner) {
        this.AAMOwner = AAMOwner;
    }

    public PlainCredentials getApplication() {
        return application;
    }

    public void setApplication(PlainCredentials application) {
        this.application = application;
    }
}
