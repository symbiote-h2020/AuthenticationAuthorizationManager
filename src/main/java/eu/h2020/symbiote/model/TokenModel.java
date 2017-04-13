package eu.h2020.symbiote.model;

import eu.h2020.symbiote.commons.json.RequestToken;
import org.springframework.data.annotation.Id;

import java.util.Date;

/**
 * Token entity definition for database persistence.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @see eu.h2020.symbiote.commons.json.RequestToken
 */
public class TokenModel {

    @Id
    private String id = "";
    private String token = "";
    private Date createdAt = new Date(0);
    private Type type = Type.NULL;

    public TokenModel() {// required by org.springframework.data.mapping.model.MappingInstantiationException
    }

    public TokenModel(String token, Date createdAt, Type type) {
        this.token = token;
        this.createdAt = createdAt;
        this.type = type;
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

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public enum Type {
        /**
         * issued by Core AAM
         */
        CORE,
        /**
         * issued in federation
         */
        FOREIGN,
        /**
         * issued by Platform AAM
         */
        HOME,
        /**
         * uninitialised value of this enum
         */
        NULL
    }
}