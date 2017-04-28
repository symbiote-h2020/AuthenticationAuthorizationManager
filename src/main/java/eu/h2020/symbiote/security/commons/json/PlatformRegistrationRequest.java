package eu.h2020.symbiote.security.commons.json;

/**
 * Created by Maks on 2017-04-26.
 */
public class PlatformRegistrationRequest {
    private LoginRequest owner;
    private String platformID;
    private String recoveryMail;
    private String platformIPAurl;

    public PlatformRegistrationRequest() {
        this.owner=null;
        this.platformID = null;
        this.recoveryMail = null;
        this.platformIPAurl = null;
    }

    public PlatformRegistrationRequest(LoginRequest owner, String preferredPlatformID, String recoveryMail, String platformIPAurl) {
        this.owner=owner;
        this.platformID = preferredPlatformID;
        this.recoveryMail = recoveryMail;
        this.platformIPAurl = platformIPAurl;
    }

    public PlatformRegistrationRequest(String username, String password, String recoveryMail, String platformIPAurl) {
        this.owner=owner;
        this.recoveryMail = recoveryMail;
        this.platformIPAurl = platformIPAurl;
    }


    public LoginRequest getOwner() {
        return owner;
    }

    public void setOwner(LoginRequest owner) {
        this.owner = owner;
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

    public String getPlatformIPAurl() {
        return platformIPAurl;
    }

    public void setPlatformIPAurl(String platformIPAurl) {
        this.platformIPAurl = platformIPAurl;
    }
}
