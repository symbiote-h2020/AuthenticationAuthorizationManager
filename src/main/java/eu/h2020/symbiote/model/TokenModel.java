package eu.h2020.symbiote.model;

/**
 * Created by Nemanja on 14.12.2016.
 */

import eu.h2020.symbiote.commons.json.RequestToken;
import org.springframework.data.annotation.Id;

public class TokenModel {

    String token;
    public TokenModel() {
        this.token = null;
    }

    public TokenModel(String token) {
        this.token = token;
    }

    public TokenModel(RequestToken token) {
        this.token = token.getToken();
    }

    @Id
    public String getToken() {
        return this.token;
    }
}