package eu.h2020.symbiote.commons.json;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Class that defines the structure of a registration response sent by CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class RegistrationResponse {

    private X509Certificate certificate;
    private PrivateKey privateKey;

    public RegistrationResponse() {
        this.certificate = null;
        this.privateKey = null;
    }

    public RegistrationResponse(X509Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String toJson(){
        ObjectMapper om = new ObjectMapper();
        try {
            return om.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
    }

}
