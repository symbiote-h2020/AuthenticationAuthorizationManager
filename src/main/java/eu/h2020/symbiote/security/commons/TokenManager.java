package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.Status;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.aam.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.aam.MalformedJWTException;
import eu.h2020.symbiote.security.exceptions.aam.TokenValidationException;
import eu.h2020.symbiote.security.payloads.CheckTokenRevocationResponse;
import eu.h2020.symbiote.security.payloads.Token;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.services.TokenService;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Class for managing operations (creation, verification checking, etc.) on
 * tokens in token related service ({@link TokenService}).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @see Token
 */
@Component
public class TokenManager {

    private static Log log = LogFactory.getLog(TokenManager.class);

    private JWTEngine jwtEngine;
    private RegistrationManager regManager;

    private PlatformRepository platformRepository;

    /**
     * Acts as either CoreAAM or acquired PlatformId for PlatformAAM
     */
    @Value("${aam.deployment.id}")
    private String deploymentId = "";

    @Value("${aam.deployment.type}")
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;

    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;

    @Autowired
    public TokenManager(RegistrationManager regManager, PlatformRepository platformRepository) {
        this.jwtEngine = new JWTEngine();
        this.regManager = regManager;
        this.platformRepository = platformRepository;
    }

    /**
     * @param user for which to issue to token
     * @return core or platform token issued for given user
     * @throws JWTCreationException on error
     */
    public Token createHomeToken(User user)
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
                            attributes.put(CoreAttributes.OWNED_PLATFORM.toString(), platformRepository
                                    .findByPlatformOwner(user).getPlatformId());
                            break;
                        case NULL:
                            throw new JWTCreationException("User Role unspecified");
                    }
                    break;
                case PLATFORM:
                    // TODO R3 federation
                    break;
                case NULL:
                    throw new JWTCreationException("Misconfigured AAM deployment type");
            }
            return new Token(jwtEngine.generateJWTToken(user.getUsername(), attributes, user.getCertificate().getX509()
                    .getPublicKey().getEncoded(), deploymentType, tokenValidity, deploymentId, regManager
                    .getAAMPublicKey(), regManager.getAAMPrivateKey()));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

    public Token createForeignToken(String foreignToken)
            throws JWTCreationException {
        try {

            JWTClaims claims = JWTEngine.getClaimsFromToken(foreignToken);

            Map<String, String> federatedAttributes = new HashMap<>();
            return new Token(
                    jwtEngine.generateJWTToken(claims.getIss(), federatedAttributes, Base64.decodeBase64(claims
                                    .getIpk()), deploymentType, tokenValidity, deploymentId, regManager
                                    .getAAMPublicKey(),
                            regManager.getAAMPrivateKey()));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

    public CheckTokenRevocationResponse checkHomeTokenRevocation(Token token, TokenEntity dbToken) {

        CheckTokenRevocationResponse outcome = new CheckTokenRevocationResponse(Status.SUCCESS);

        try {
            if (dbToken == null) {
                throw new TokenValidationException(AAMConstants.ERR_TOKEN_WRONG_ISSUER);
            }
            JWTClaims claims = JWTEngine.getClaimsFromToken(token.getToken());

            //Check if token expired
            Long now = System.currentTimeMillis();
            if ((claims.getExp() < now || (claims.getIat() > now))) {
                throw new TokenValidationException(AAMConstants.ERR_TOKEN_EXPIRED);
            }

            //Check if issuer of the token is this platform
            if (!claims.getIss().equals(deploymentId)) {
                throw new TokenValidationException(AAMConstants.ERR_TOKEN_WRONG_ISSUER);
            }
            return outcome;
        } catch (MalformedJWTException e) {
            log.error("JWT Format error", e);
        } catch (TokenValidationException e) {
            log.error("JWT validation error", e);
        }

        outcome.setStatus(Status.FAILURE);

        return outcome;
    }

}
