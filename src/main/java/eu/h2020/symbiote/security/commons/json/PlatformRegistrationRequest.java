package eu.h2020.symbiote.security.commons.json;

/**
 * Created by Maks on 2017-04-26.
 */
public class PlatformRegistrationRequest {
    private String username;
    private String password;
    private String platformID;
    private String recoveryMail;
    private String platformIPAurl;

    public PlatformRegistrationRequest() {
        this.username = null;
        this.password = null;
        this.platformID = null;
        this.recoveryMail = null;
        this.platformIPAurl = null;
    }

    public PlatformRegistrationRequest(String username, String password, String platformID, String recoveryMail, String platformIPAurl) {
        this.username = username;
        this.password = password;
        this.platformID = platformID;
        this.recoveryMail = recoveryMail;
        this.platformIPAurl = platformIPAurl;
    }

    public PlatformRegistrationRequest(String username, String password, String recoveryMail, String platformIPAurl) {
        this.username = username;
        this.password = password;
        this.recoveryMail = recoveryMail;
        this.platformIPAurl = platformIPAurl;
    }


    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
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

    @Override
    public String toString() {
        return "PlatformRegistrationRequest [username=" + username + ", password=" + password + ", platformID=" + platformID
                + ", recoveryMail=" + recoveryMail + ", platformIPAurl=" + platformIPAurl + "]";
    }
}
