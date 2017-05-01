package eu.h2020.symbiote.security.commons;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;

/**
 * SymbIoTe-enabled IoT platform registered in the Core AAM.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class Platform {

    @Id
    private String platformId = "";
    private String platformAAMURL = "";
    @DBRef
    private User platformOwner;

    /**
     * @param platformId     SymbIoTe-unique platform identifier
     * @param platformAAMURL Address where the Platform exposes its {@link eu.h2020.symbiote.security.AuthenticationAuthorizationManager}
     * @param platformOwner  details of the Platform Owner
     */
    public Platform(String platformId, String platformAAMURL, User platformOwner) {
        this.platformId = platformId;
        this.platformAAMURL = platformAAMURL;
        this.platformOwner = platformOwner;
    }

    /**
     * @return SymbIoTe-unique platform identifier
     */
    public String getPlatformId() {
        return platformId;
    }

    public void setPlatformId(String platformId) {
        this.platformId = platformId;
    }

    /**
     * @return Address where the Platform exposes its {@link eu.h2020.symbiote.security.AuthenticationAuthorizationManager}
     */
    public String getPlatformAAMURL() {
        return platformAAMURL;
    }

    public void setPlatformAAMURL(String platformAAMURL) {
        this.platformAAMURL = platformAAMURL;
    }
}
