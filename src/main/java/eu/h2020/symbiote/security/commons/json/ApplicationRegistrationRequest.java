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
    private String federatedID = "";
    private String recoveryMail = "";

    /**
     * used by JSON serializer
     */
    public ApplicationRegistrationRequest() { // used by JSON serializer
    }

    public ApplicationRegistrationRequest(PlainCredentials aamOwnerCredentials, PlainCredentials
            applicationCredentials, String federatedID, String
                                                  recoveryMail) {
        AAMOwnerCredentials = aamOwnerCredentials;
        this.applicationCredentials = applicationCredentials;
        this.federatedID = federatedID;
        this.recoveryMail = recoveryMail;
    }


    public PlainCredentials getApplicationCredentials() {
        return applicationCredentials;
    }

    public void setApplicationCredentials(PlainCredentials applicationCredentials) {
        this.applicationCredentials = applicationCredentials;
    }

    public String getPlatformID() {
        return federatedID;
    }

    public void setPlatformID(String platformID) {
        this.federatedID = platformID;
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
