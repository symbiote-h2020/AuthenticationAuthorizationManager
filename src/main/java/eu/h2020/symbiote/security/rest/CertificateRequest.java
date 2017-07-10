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

}
