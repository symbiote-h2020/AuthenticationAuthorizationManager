package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.MalformedJWTException;
import eu.h2020.symbiote.security.commons.json.RequestToken;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.springframework.data.annotation.Id;

import java.util.Date;

/**
 * Token entity.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @see RequestToken
 */
public class Token {

    private static Log log = LogFactory.getLog(Token.class);

    @Id
    private String id = "";
    private String token = "";
    private Date createdAt = new Date(0);
    private IssuingAuthorityType type = IssuingAuthorityType.NULL;

    /**
     * required by JPA
     */
    public Token() {
        // required by JPA
    }

    public Token(RequestToken requestToken) {
        this.token = requestToken.getToken();
        try {
            this.createdAt = new Date(JWTEngine.getClaimsFromToken(token).getIat());
        } catch (MalformedJWTException | JSONException e) {
            e.printStackTrace();
            log.error("Token creation error", e);
        }
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

    public IssuingAuthorityType getType() {
        return type;
    }

    public void setType(IssuingAuthorityType type) {
        this.type = type;
    }

}