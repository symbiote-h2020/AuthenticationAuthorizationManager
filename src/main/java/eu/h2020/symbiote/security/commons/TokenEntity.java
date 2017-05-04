package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.exceptions.aam.MalformedJWTException;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.data.annotation.Id;

import java.util.Date;

/**
 * Token Entity.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class TokenEntity {

    private static Log log = LogFactory.getLog(TokenEntity.class);

    @Id
    private String id = "";
    private String token = "";
    private Date createdAt = new Date(0);
    private IssuingAuthorityType type = IssuingAuthorityType.NULL;

    /**
     * required by JPA
     */
    public TokenEntity() {
        // required by JPA
    }

    public TokenEntity(String token) {
        this.token = token;
        try {
            this.id = JWTEngine.getClaimsFromToken(token).getJti();
            this.createdAt = new Date(JWTEngine.getClaimsFromToken(this.token).getIat());
        } catch (MalformedJWTException e) {
            log.error("TokenEntity creation error", e);
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