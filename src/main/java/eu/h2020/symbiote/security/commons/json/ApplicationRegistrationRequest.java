package eu.h2020.symbiote.security.commons.json;

/**
 * //TODO missing javadocs
 * Created on 2017-04-28.
 * @author Maksymilian Marcinowski (PSNC)
 */
public class ApplicationRegistrationRequest {
    private PlainCredentials applicationCredentials = new PlainCredentials();
    private String federatedID = "";
    private String recoveryMail = "";

    public ApplicationRegistrationRequest(PlainCredentials applicationCredentials, String federatedID, String
            recoveryMail) {
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


}
