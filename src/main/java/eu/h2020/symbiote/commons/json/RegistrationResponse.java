package eu.h2020.symbiote.commons.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Class that defines the structure of a registration response sent by CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class RegistrationResponse {

    private String pemCertificate;
    private String pemPrivateKey;

    public RegistrationResponse() {
        this.pemCertificate = null;
        this.pemPrivateKey = null;
    }

    public RegistrationResponse(String pemCertificate, String pemPrivateKey) {
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
            e.printStackTrace();
            return null;
        }
    }

}
