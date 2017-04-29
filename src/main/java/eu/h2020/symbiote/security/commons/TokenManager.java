package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.commons.enums.Status;
import eu.h2020.symbiote.security.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.TokenValidationException;
import eu.h2020.symbiote.security.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.security.commons.json.RequestToken;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.services.TokenService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Class for managing operations (creation, verification checking, etc.) on
 * {@link RequestToken} objects in token related
 * service ({@link TokenService}).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @see RequestToken
 */
@Component
public class TokenManager {

    private static Log log = LogFactory.getLog(TokenManager.class);

    private final JWTEngine jwtEngine;
    private RegistrationManager regManager;

    /**
     * Acts as either CoreAAM or acquired PlatformId for PlatformAAM
     */
    @Value("${aam.deployment.id}")
    private String deploymentId = "";


    @Autowired
    public TokenManager(JWTEngine jwtEngine, RegistrationManager regManager) {
        this.jwtEngine = jwtEngine;
        this.regManager = regManager;
    }

    /**
     * Used to create CORE & PLATFORM tokens
     *
     * @return
     * @throws JWTCreationException
     */
    public RequestToken createHomeToken()
            throws JWTCreationException {
        try {
            return new RequestToken(
                    jwtEngine.generateJWTToken(deploymentId, null, regManager.getAAMPublicKey().getEncoded()));
        } catch (Exception e) {
            throw new JWTCreationException();
        }
    }

    public RequestToken createForeignToken(String foreignToken)
            throws JWTCreationException {
        try {

            JWTClaims claims = jwtEngine.getClaimsFromToken(foreignToken);

            return new RequestToken(
                    jwtEngine.generateJWTToken(claims.getIss(), null, claims.getIpk().getBytes()));
        } catch (Exception e) {
            throw new JWTCreationException();
        }
    }

    public CheckTokenRevocationResponse checkHomeTokenRevocation(RequestToken token, Token dbToken) {

        CheckTokenRevocationResponse outcome = new CheckTokenRevocationResponse(Status.SUCCESS);

        try {
            if (dbToken == null) {
                throw new TokenValidationException(Constants.ERR_TOKEN_WRONG_ISSUER);
            }
            JWTClaims claims = jwtEngine.getClaimsFromToken(token.getToken());
            //Check if token expired
            Long now = System.currentTimeMillis();
            if ((claims.getExp() < now || (claims.getIat() > now))) {
                throw new TokenValidationException(Constants.ERR_TOKEN_EXPIRED);
            }

            //Check if issuer of the token is this platform
            if (!claims.getIss().equals(deploymentId)) {
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
