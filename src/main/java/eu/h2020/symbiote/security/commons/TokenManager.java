package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.aam.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.aam.MalformedJWTException;
import eu.h2020.symbiote.security.exceptions.aam.TokenValidationException;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.services.TokenService;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Class for managing operations (creation, verification checking, etc.) on
 * tokens in token related service ({@link TokenService}).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
@Component
public class TokenManager {

    private static Log log = LogFactory.getLog(TokenManager.class);

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
                                    .findByPlatformOwner(user).getPlatformInstanceId());
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
            return new Token(JWTEngine.generateJWTToken(user.getUsername(), attributes, user.getCertificate().getX509()
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
                    JWTEngine.generateJWTToken(claims.getIss(), federatedAttributes, Base64.decodeBase64(claims
                                    .getIpk()), deploymentType, tokenValidity, deploymentId, regManager
                                    .getAAMPublicKey(),
                            regManager.getAAMPrivateKey()));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

    public CheckRevocationResponse checkHomeTokenRevocation(Token token, Token dbToken) {

        CheckRevocationResponse outcome = new CheckRevocationResponse(ValidationStatus.VALID);

        try {
            if (dbToken == null) {
                throw new TokenValidationException(AAMConstants.ERR_TOKEN_WRONG_ISSUER);
            }
            JWTClaims claims = JWTEngine.getClaimsFromToken(dbToken.getToken());
            //Convert IPK claim to publicKey for validation
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(claims.getIpk()));
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);

            switch (JWTEngine.validateToken(token, pubKey)) {
                case VALID:
                    outcome.setStatus(ValidationStatus.VALID);
                    break;
                case EXPIRED:
                    outcome.setStatus(ValidationStatus.EXPIRED);
                    break;
                case REVOKED:
                    outcome.setStatus(ValidationStatus.REVOKED);
                    break;
                case INVALID:
                    outcome.setStatus(ValidationStatus.INVALID);
                    break;

            }
            //Check if issuer of the token is this platform
            if (!claims.getIss().equals(deploymentId)) {
                outcome.setStatus(ValidationStatus.INVALID);
            }
        } catch (MalformedJWTException | TokenValidationException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("JWT validation error", e);
            outcome.setStatus(ValidationStatus.INVALID);
        }
        return outcome;
    }

}
