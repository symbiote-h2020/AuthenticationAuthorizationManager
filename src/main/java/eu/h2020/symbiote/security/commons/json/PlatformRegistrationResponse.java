package eu.h2020.symbiote.security.commons.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Describes a response for platform registration sent by AAM
 */
public class PlatformRegistrationResponse {

    private String pemCertificate;
    private String pemPrivateKey;
    private String platformId;

    public PlatformRegistrationResponse() {
        this.pemCertificate = null;
        this.pemPrivateKey = null;
    }

    public PlatformRegistrationResponse(String pemCertificate, String pemPrivateKey) {
        this.pemCertificate = pemCertificate;
        this.pemPrivateKey = pemPrivateKey;
    }

    public PlatformRegistrationResponse(String pemCertificate, String pemPrivateKey, String generatedId) {
        this.pemCertificate = pemCertificate;
        this.pemPrivateKey = pemPrivateKey;
        this.platformId = generatedId;
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

    public String getPlatformId() {
        return platformId;
    }

    public void setPlatformId(String platformId) {
        this.platformId = platformId;
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
