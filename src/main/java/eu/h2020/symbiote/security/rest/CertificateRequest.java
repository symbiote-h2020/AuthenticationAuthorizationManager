package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.session.AAM;

/**
 * Created by Maks on 2017-06-18.
 */
public class CertificateRequest {

    private AAM homeAAM;
    private String username;
    private String password;
    private String clientId;
    private String clientCSR;

    public CertificateRequest(AAM homeAAM, String username, String password, String clientId, String clientCSR){
        this.homeAAM=homeAAM;
        this.username=username;
        this.password=password;
        this.clientId=clientId;
        this.clientCSR=clientCSR;
    }


    public AAM getHomeAAM() {
        return homeAAM;
    }

    public void setHomeAAM(AAM homeAAM) {
        this.homeAAM = homeAAM;
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
