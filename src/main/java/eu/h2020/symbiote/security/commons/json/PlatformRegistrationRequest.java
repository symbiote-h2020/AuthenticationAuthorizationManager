package eu.h2020.symbiote.security.commons.json;

/**
 * Describes platform registration in AAM payload.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Maksymilian Marcinowski (PSNC)
 */
public class PlatformRegistrationRequest {
    private PlainCredentials platformOwnerPlainCredentials = new PlainCredentials();
    private String platformID = "";
    private String recoveryMail = "";
    private String platformIPAURL = "";

    /**
     * For use when a Platform Owner wants a preferred platform identifier
     *
     * @param platformOwnerPlainCredentials
     * @param preferredPlatformID
     * @param recoveryMail
     * @param platformIPAURL
     */
    public PlatformRegistrationRequest(PlainCredentials platformOwnerPlainCredentials, String preferredPlatformID,
                                       String recoveryMail, String
                                               platformIPAURL) {
        this.platformOwnerPlainCredentials = platformOwnerPlainCredentials;
        this.platformID = preferredPlatformID;
        this.recoveryMail = recoveryMail;
        this.platformIPAURL = platformIPAURL;
    }

    /**
     * For use when Platform Owner registers and used generated platform identifier
     *
     * @param platformOwnerPlainCredentials
     * @param recoveryMail
     * @param platformIPAURL
     */
    public PlatformRegistrationRequest(PlainCredentials platformOwnerPlainCredentials, String recoveryMail, String
            platformIPAURL) {
        this.platformOwnerPlainCredentials = platformOwnerPlainCredentials;
        this.recoveryMail = recoveryMail;
        this.platformIPAURL = platformIPAURL;
    }


    public PlainCredentials getPlatformOwnerPlainCredentials() {
        return platformOwnerPlainCredentials;
    }

    public void setPlatformOwnerPlainCredentials(PlainCredentials platformOwnerPlainCredentials) {
        this.platformOwnerPlainCredentials = platformOwnerPlainCredentials;
    }

    public String getPlatformID() {
        return platformID;
    }

    public void setPlatformID(String platformID) {
        this.platformID = platformID;
    }

    public String getRecoveryMail() {
        return recoveryMail;
    }

    public void setRecoveryMail(String recoveryMail) {
        this.recoveryMail = recoveryMail;
    }

    public String getPlatformIPAURL() {
        return platformIPAURL;
    }

    public void setPlatformIPAURL(String platformIPAURL) {
        this.platformIPAURL = platformIPAURL;
    }
}
