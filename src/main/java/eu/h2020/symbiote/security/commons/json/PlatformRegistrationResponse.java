package eu.h2020.symbiote.security.commons.json;

/**
 * Describes a response for platform registration sent by AAM
 *
 * @author Maksymilian Marcinowski (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class PlatformRegistrationResponse {
    private String pemCertificate = "";
    private String pemPrivateKey = "";
    private String platformId = "";

    public PlatformRegistrationResponse() {
        // used by serializer
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

}
