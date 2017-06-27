package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.session.AAM;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;

/**
 * Created by Maks on 2017-06-18.
 */
public class CertificateRequest {

    private AAM homeAAM;
    private String username;
    private String password;
    private String clientId;
    private String clientCSR;

    public CertificateRequest(){
        // required by json
    }
    public CertificateRequest(String username, String password, String clientId, PKCS10CertificationRequest clientCSR) throws IOException {
        this.username=username;
        this.password=password;
        this.clientId=clientId;
        this.clientCSR= Base64.encodeBase64String(clientCSR.getEncoded());
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientCSR() {
        return clientCSR;
    }

    public void setClientCSR(String clientCSR) {
        this.clientCSR = clientCSR;
    }
}
