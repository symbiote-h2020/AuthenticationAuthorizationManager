package eu.h2020.symbiote.security.commons;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;

/**
 * SymbIoTe-enabled IoT platform instance registered in the Core AAM.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class Platform {

    @Id
    private String platformInstanceId = "";
    private String platformAAMURL = "";
    private String platformInstanceFriendlyName;
    @DBRef
    private User platformOwner;

    /**
     * @param platformInstanceId           SymbIoTe-unique platform identifier
     * @param platformAAMURL               Address where the Platform exposes its AAM
     * @param platformInstanceFriendlyName a label for the end user to be able to identify the login endrypoint
     * @param platformOwner                details of the Platform Owner
     */
    public Platform(String platformInstanceId, String platformAAMURL, String platformInstanceFriendlyName, User
            platformOwner) {
        this.platformInstanceId = platformInstanceId;
        this.platformAAMURL = platformAAMURL;
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
        this.platformOwner = platformOwner;
    }

    /**
     * @return SymbIoTe-unique platform identifier
     */
    public String getPlatformInstanceId() {
        return platformInstanceId;
    }

    public void setPlatformInstanceId(String platformInstanceId) {
        this.platformInstanceId = platformInstanceId;
    }

    /**
     * @return Address where the Platform exposes its AAM
     */
    public String getPlatformAAMURL() {
        return platformAAMURL;
    }

    public void setPlatformAAMURL(String platformAAMURL) {
        this.platformAAMURL = platformAAMURL;
    }

    public User getPlatformOwner() {
        return platformOwner;
    }

    public void setPlatformOwner(User platformOwner) {
        this.platformOwner = platformOwner;
    }

    /**
     * @return a label for the end user to be able to identify the login endrypoint
     */
    public String getPlatformInstanceFriendlyName() {
        return platformInstanceFriendlyName;
    }

    public void setPlatformInstanceFriendlyName(String platformInstanceFriendlyName) {
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
    }
}
