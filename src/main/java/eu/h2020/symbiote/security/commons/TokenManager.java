package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.Status;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.TokenValidationException;
import eu.h2020.symbiote.security.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.security.commons.json.RequestToken;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.commons.jwt.attributes.CoreAttributes;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.services.TokenService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

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

    private PlatformRepository platformRepository;

    /**
     * Acts as either CoreAAM or acquired PlatformId for PlatformAAM
     */
    @Value("${aam.deployment.id}")
    private String deploymentId = "";

    @Value("${aam.deployment.type}")
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;


    @Autowired
    public TokenManager(JWTEngine jwtEngine, RegistrationManager regManager, PlatformRepository platformRepository) {
        this.jwtEngine = jwtEngine;
        this.regManager = regManager;
        this.platformRepository = platformRepository;
    }

    /**
     * Used to create CORE & PLATFORM tokens
     *
     * @param user
     * @return
     * @throws JWTCreationException
     */
    public RequestToken createHomeToken(User user)
            throws JWTCreationException {
        try {
            Map<String, String> attributes = new HashMap<>();

            switch (deploymentType) {
                case CORE:
                    switch (user.getRole()) {
                        case APPLICATION:
                            attributes.put(CoreAttributes.ROLE.toString(), UserRole.APPLICATION.toString());
                            break;
                        case PLATFORM_OWNER:
                            attributes.put(CoreAttributes.ROLE.toString(), UserRole.PLATFORM_OWNER.toString());
                            attributes.put(CoreAttributes.OWNED_PLATFORM.toString(), platformRepository.findByPlatformOwner(user).getPlatformId());
                            break;
                        case NULL:
                            throw new JWTCreationException("User Role unspecified");
                    }
                    break;
                case PLATFORM:
                    // TODO not that I know of any
                    break;
                case NULL:
                    // TODO not that I know of any
                    break;
            }

            // TODO make use of User's public Certificate
            return new RequestToken(
                    jwtEngine.generateJWTToken(deploymentId, attributes, regManager.getAAMPublicKey().getEncoded()));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

    public RequestToken createForeignToken(String foreignToken)
            throws JWTCreationException {
        try {

            JWTClaims claims = JWTEngine.getClaimsFromToken(foreignToken);

            return new RequestToken(
                    jwtEngine.generateJWTToken(claims.getIss(), null, claims.getIpk().getBytes()));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

    public CheckTokenRevocationResponse checkHomeTokenRevocation(RequestToken token, Token dbToken) {

        CheckTokenRevocationResponse outcome = new CheckTokenRevocationResponse(Status.SUCCESS);

        try {
            if (dbToken == null) {
                throw new TokenValidationException(Constants.ERR_TOKEN_WRONG_ISSUER);
            }
            JWTClaims claims = JWTEngine.getClaimsFromToken(token.getToken());
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
