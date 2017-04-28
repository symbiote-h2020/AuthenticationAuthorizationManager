package eu.h2020.symbiote.security.commons.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Created by Maks on 2017-04-28.
 */
public class ApplicationRegistrationResponse {
    private String pemCertificate;
    private String pemPrivateKey;

    public ApplicationRegistrationResponse() {
        this.pemCertificate = null;
        this.pemPrivateKey = null;
    }

    public ApplicationRegistrationResponse(String pemCertificate, String pemPrivateKey) {
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
