package eu.h2020.symbiote.security.commons.json;

/**
 * Created by Maks on 2017-04-28.
 */
public class ApplicationRegistrationRequest {
    private LoginRequest owner;
    private String federatedID;
    private String recoveryMail;

    public ApplicationRegistrationRequest() {
        this.owner=null;
        this.federatedID = null;
        this.recoveryMail = null;
    }

    public ApplicationRegistrationRequest(LoginRequest owner, String federatedID, String recoveryMail) {
        this.owner=owner;
        this.federatedID = federatedID;
        this.recoveryMail = recoveryMail;
    }


    public LoginRequest getOwner() {
        return owner;
    }

    public void setOwner(LoginRequest owner) {
        this.owner = owner;
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
