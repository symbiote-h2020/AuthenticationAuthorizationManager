package eu.h2020.symbiote.model;

import org.springframework.data.annotation.Id;
import eu.h2020.symbiote.commons.json.RequestToken;

import java.util.Date;

/**
 * Token entity definition for database persistence.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see eu.h2020.symbiote.commons.json.RequestToken
 */
public class TokenModel {

    @Id
    private String id;
    private String token;
    private Date createdAt;

    public TokenModel() {
        this.token = null;
    }

    public TokenModel(String token, Date createdAt) {
        this.token = token;
        this.createdAt = createdAt;
    }

    public TokenModel(RequestToken token) {
        this.token = token.getToken();
        this.createdAt = new Date();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }
}