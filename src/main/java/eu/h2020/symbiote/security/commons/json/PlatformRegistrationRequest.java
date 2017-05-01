package eu.h2020.symbiote.security.commons.json;

/**
 * Describes platform registration in AAM payload.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Maksymilian Marcinowski (PSNC)
 */
public class PlatformRegistrationRequest {
    private Credentials AAMOwnerCredentials = new Credentials();
    private UserDetails platformOwnerDetails = new UserDetails();
    private String platformAAMURL = "";
    private String platformId = "";


    public PlatformRegistrationRequest() {
        // required for serialization
    }

    /**
     * For use when a Platform Owner is fine with generated platform identifier
     *
     * @param AAMOwnerCredentials  used to authorize this request
     * @param platformOwnerDetails used to register the platform owner in the database
     * @param platformAAMURL       used to point symbiote users to possible login entrypoints
     */
    public PlatformRegistrationRequest(Credentials AAMOwnerCredentials, UserDetails platformOwnerDetails, String platformAAMURL) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
        this.platformOwnerDetails = platformOwnerDetails;
        this.platformAAMURL = platformAAMURL;
    }

    /**
     * For use when a Platform Owner wants a preferred platform identifier
     * * @param AAMOwnerCredentials used to authorize this request
     *
     * @param platformOwnerDetails used to register the platform owner in the database
     * @param platformAAMURL       used to point symbiote users to possible login entrypoints
     * @param preferredPlatformID  when a Platform Owner preferres his own platform identifier
     */
    public PlatformRegistrationRequest(Credentials AAMOwnerCredentials, UserDetails platformOwnerDetails, String platformAAMURL, String preferredPlatformID) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
        this.platformId = preferredPlatformID;
        this.platformAAMURL = platformAAMURL;
        this.platformOwnerDetails = platformOwnerDetails;
    }

    public UserDetails getPlatformOwnerDetails() {
        return platformOwnerDetails;
    }

    public void setPlatformOwnerDetails(UserDetails platformOwnerDetails) {
        this.platformOwnerDetails = platformOwnerDetails;
    }

    public String getPlatformId() {
        return platformId;
    }

    public void setPlatformId(String platformId) {
        this.platformId = platformId;
    }

    public String getPlatformAAMURL() {
        return platformAAMURL;
    }

    public void setPlatformAAMURL(String platformAAMURL) {
        this.platformAAMURL = platformAAMURL;
    }

    public Credentials getAAMOwnerCredentials() {
        return AAMOwnerCredentials;
    }

    public void setAAMOwnerCredentials(Credentials AAMOwnerCredentials) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
    }
}