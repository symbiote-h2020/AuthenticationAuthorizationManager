package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.session.AAM;
import lombok.*;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;


import java.io.IOException;

/**
 * Created by Maks on 2017-06-18.
 */
public  @NoArgsConstructor  @AllArgsConstructor @Getter @Setter
class CertificateRequest {

    private String username;
    private String password;
    private String clientId;
    private String clientCSR;

    /**
     *
     * @param username
     * @param password
     * @param clientId
     * @param clientCSR
     * @throws IOException
     */
    public CertificateRequest(String username, String password, String clientId, PKCS10CertificationRequest clientCSR) throws IOException {
        this.username=username;
        this.password=password;
        this.clientId=clientId;
        this.clientCSR= Base64.encodeBase64String(clientCSR.getEncoded());
    }

}
