package eu.h2020.symbiote.security.commons.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Class that defines the structure of a user registration response sent by AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class UserRegistrationResponse {

    private static Log log = LogFactory.getLog(UserRegistrationResponse.class);

    // TODO Release 3 fix to support CertificateSignRequests
    private String pemCertificate = "";
    private String pemPrivateKey = "";

    /**
     * required for JSON serialization
     */
    public UserRegistrationResponse() {
        // required by JSON
    }

    public UserRegistrationResponse(String pemCertificate, String pemPrivateKey) {
        this.pemCertificate = pemCertificate;
        this.pemPrivateKey = pemPrivateKey;
    }

    public String getPemCertificate() {
        return pemCertificate;
    }

    public void setPemCertificate(String pemCertificate) {
        this.pemCertificate = pemCertificate;
    }

    public String getPemPrivateKey() {
        return pemPrivateKey;
    }

    public void setPemPrivateKey(String pemPrivateKey) {
        this.pemPrivateKey = pemPrivateKey;
    }

    public String toJson() {
        ObjectMapper om = new ObjectMapper();
        try {
            return om.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            log.error("Error converting UserRegistrationResponse to JSON", e);
            return null;
        }
    }

}
