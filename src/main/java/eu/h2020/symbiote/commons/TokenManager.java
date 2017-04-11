package eu.h2020.symbiote.commons;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

import eu.h2020.symbiote.commons.exceptions.MalformedJWTException;
import eu.h2020.symbiote.commons.exceptions.TokenValidationException;
import eu.h2020.symbiote.commons.jwt.JWTClaims;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import eu.h2020.symbiote.commons.enums.Status;
import eu.h2020.symbiote.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.commons.jwt.JWTEngine;

/**
 * Class for managing operations (creation, verification checking, etc.) on
 * {@link eu.h2020.symbiote.commons.json.RequestToken} objects in token related
 * service ({@link eu.h2020.symbiote.services.TokenService}).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see eu.h2020.symbiote.commons.json.RequestToken
 */
@Component
public class TokenManager {

    private static Log log = LogFactory.getLog(TokenManager.class);

    private final JWTEngine jwtEngine;
    private RegistrationManager regManager;

    @Value("${platform.id}")
    private String platformId;


    @Autowired
    public TokenManager(JWTEngine jwtEngine, RegistrationManager regManager) {
        this.jwtEngine = jwtEngine;
        this.regManager = regManager;
    }

    public RequestToken create(String appId, Map<String, Object> claimsMap)
            throws JWTCreationException {
        String appDummyCert;
        try {

            return new RequestToken(
                    jwtEngine.generateJWTToken(appId, claimsMap, regManager.getPlatformAAMPublicKey().getEncoded()));
        } catch (Exception e) {
            throw new JWTCreationException();
        }
    }

    public CheckTokenRevocationResponse checkHomeTokenRevocation(RequestToken token) {

        CheckTokenRevocationResponse outcome = new CheckTokenRevocationResponse(Status.SUCCESS);

        try {
            JWTClaims claims = jwtEngine.getClaimsFromToken(token.getToken());
            //Check if token expired
            Long now = System.currentTimeMillis();
            if ((claims.getExp() < now || (claims.getIat() > now))) {
                throw new TokenValidationException(Constants.ERR_TOKEN_EXPIRED);
            }

            //Check if issuer of the token is this platform
            if (!claims.getIss().equals(platformId)) {
                throw new TokenValidationException(Constants.ERR_TOKEN_WRONG_ISSUER);
            }
            return outcome;
        } catch (MalformedJWTException e) {
            log.error("JWT Format error: " + e.toString());
        } catch (JSONException e) {
            log.error("JWT data reading error: " + e.toString());
        } catch (TokenValidationException e) {
            log.error("JWT validation error: " + e.toString());
        }

        outcome.setStatus(Status.FAILURE);

        return outcome;
    }

}
