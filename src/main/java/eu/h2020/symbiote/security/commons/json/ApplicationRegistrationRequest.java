package eu.h2020.symbiote.security.commons.json;

/**
 * Describes application registration in AAM payload.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Maksymilian Marcinowski (PSNC)
 */
public class ApplicationRegistrationRequest {

    private PlainCredentials AAMOwnerCredentials = new PlainCredentials();

    // TODO Release 3 fix to support CertificateSignRequests
    private PlainCredentials applicationCredentials = new PlainCredentials();
    private String federatedId = "";
    private String recoveryMail = "";

    /**
     * used by JSON serializer
     */
    public ApplicationRegistrationRequest() { // used by JSON serializer
    }

    public ApplicationRegistrationRequest(PlainCredentials AAMOwnerCredentials, PlainCredentials
            applicationCredentials, String federatedId, String
                                                  recoveryMail) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
        this.applicationCredentials = applicationCredentials;
        this.federatedId = federatedId;
        this.recoveryMail = recoveryMail;
    }


    public PlainCredentials getApplicationCredentials() {
        return applicationCredentials;
    }

    public void setApplicationCredentials(PlainCredentials applicationCredentials) {
        this.applicationCredentials = applicationCredentials;
    }

    public String getFederatedId() {
        return federatedId;
    }

    public void setFederatedID(String federatedId) {
        this.federatedId = federatedId;
    }

    public String getRecoveryMail() {
        return recoveryMail;
    }

    public void setRecoveryMail(String recoveryMail) {
        this.recoveryMail = recoveryMail;
    }


    public PlainCredentials getAAMOwnerCredentials() {
        return AAMOwnerCredentials;
    }

    public void setAAMOwnerCredentials(PlainCredentials AAMOwnerCredentials) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
    }
}
