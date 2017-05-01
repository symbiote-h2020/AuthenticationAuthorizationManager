package eu.h2020.symbiote.security.commons.json;

/**
 * Describes user registration in AAM payload.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Maksymilian Marcinowski (PSNC)
 */
public class UserRegistrationRequest {

    private Credentials AAMOwnerCredentials = new Credentials();
    // TODO Release 3 fix to support CertificateSignRequests
    private UserDetails userDetails = new UserDetails();

    /**
     * used by JSON serializer
     */
    public UserRegistrationRequest() { // used by JSON serializer
    }

    public UserRegistrationRequest(Credentials AAMOwnerCredentials, UserDetails userDetails) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
        this.userDetails = userDetails;
    }

    public Credentials getAAMOwnerCredentials() {
        return AAMOwnerCredentials;
    }

    public void setAAMOwnerCredentials(Credentials AAMOwnerCredentials) {
        this.AAMOwnerCredentials = AAMOwnerCredentials;
    }

    public UserDetails getUserDetails() {
        return userDetails;
    }

    public void setUserDetails(UserDetails userDetails) {
        this.userDetails = userDetails;
    }
}
