package eu.h2020.symbiote.model;

import eu.h2020.symbiote.commons.json.RequestToken;
import org.springframework.data.annotation.Id;


/**
 * Token entity definition for database persistence.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see eu.h2020.symbiote.commons.json.RequestToken
 */
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