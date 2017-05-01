package eu.h2020.symbiote.security.commons.json;

/**
 * Describes platform registration in AAM payload.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Maksymilian Marcinowski (PSNC)
 */
public class PlatformRegistrationRequest {
    private Credentials platformOwnerCredentials = new Credentials();
    private String federatedID = "";
    private String platformID = "";
    private String recoveryMail = "";
    private String platformIPAURL = "";

    /**
     * For use when a Platform Owner wants a preferred platform identifier
     *
     * @param platformOwnerCredentials
     * @param preferredPlatformID
     * @param recoveryMail
     * @param platformIPAURL
     */
    public PlatformRegistrationRequest(Credentials platformOwnerCredentials, String federatedID, String preferredPlatformID,
                                       String recoveryMail, String
                                               platformIPAURL) {
        this.platformOwnerCredentials = platformOwnerCredentials;
        this.federatedID = federatedID;
        this.platformID = preferredPlatformID;
        this.recoveryMail = recoveryMail;
        this.platformIPAURL = platformIPAURL;
    }

    /**
     * For use when Platform Owner registers and used generated platform identifier
     *
     * @param platformOwnerCredentials
     * @param recoveryMail
     * @param platformIPAURL
     */
    public PlatformRegistrationRequest(Credentials platformOwnerCredentials, String federatedID, String recoveryMail, String
            platformIPAURL) {
        this.platformOwnerCredentials = platformOwnerCredentials;
        this.federatedID = federatedID;
        this.recoveryMail = recoveryMail;
        this.platformIPAURL = platformIPAURL;
    }


    public Credentials getPlatformOwnerCredentials() {
        return platformOwnerCredentials;
    }

    public void setPlatformOwnerCredentials(Credentials platformOwnerCredentials) {
        this.platformOwnerCredentials = platformOwnerCredentials;
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

    public String getFederatedID() {
        return federatedID;
    }

    public void setFederatedID(String federatedID) {
        this.federatedID = federatedID;
    }
}
