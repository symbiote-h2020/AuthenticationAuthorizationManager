package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.aam.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.aam.TokenValidationException;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.RevokedTokensRepository;
import eu.h2020.symbiote.security.services.TokenService;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import io.jsonwebtoken.Claims;
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
 */
@Component
public class TokenManager {

    private static Log log = LogFactory.getLog(TokenManager.class);
    private RegistrationManager regManager;
    private PlatformRepository platformRepository;
    private String deploymentId = "";
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;
    private RevokedKeysRepository revokedKeysRepository;
    private RevokedTokensRepository revokedTokensRepository;

    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;

    @Autowired
    public TokenManager(RegistrationManager regManager, PlatformRepository platformRepository, RevokedKeysRepository revokedKeysRepository, RevokedTokensRepository revokedTokensRepository) {
        this.regManager = regManager;
        this.deploymentId = regManager.getAAMInstanceIdentifier();
        this.deploymentType = regManager.getDeploymentType();
        this.platformRepository = platformRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.revokedTokensRepository = revokedTokensRepository;
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
            // TODO R3 Attribute Mapping Function
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

    public CheckRevocationResponse checkHomeTokenRevocation(String tokenString) {
        try {
            // basic validation (signature and exp)
            ValidationStatus validationStatus = JWTEngine.validateTokenString(tokenString);
            if (validationStatus != ValidationStatus.VALID) {
                return new CheckRevocationResponse(validationStatus);
            }

            Claims claims = JWTEngine.getClaims(tokenString);
            // flow for Platform AAM
            if (deploymentType != IssuingAuthorityType.CORE) {
                if (!deploymentId.equals(claims.getIssuer())) {
                    // todo think of better status for foreign token which we should not validate (maybe exception?)
                    return new CheckRevocationResponse(ValidationStatus.INVALID);
                }
                // todo check IPK equals current AAM PK
                //regManager.getAAMCertificate().getPublicKey().getEncoded()
                // todo R3 possible validation of revoked IPK from CoreAAM - check if IPK was not revoked in the core
            } else {
                // check revoked IPK
                if (revokedKeysRepository.exists(claims.getIssuer())) {
                    // todo check if IPK is in the revoked set
                    // return new CheckRevocationResponse(ValidationStatus.REVOKED);
                }
            }
            // check revoked JTI
            if (revokedTokensRepository.exists(claims.getId())) {
                return new CheckRevocationResponse(ValidationStatus.REVOKED);
            }
            // check revoked SPK
            if (revokedKeysRepository.exists(claims.getSubject())) {
                // todo check if SPK is is in the revoked set
                // return new CheckRevocationResponse(ValidationStatus.REVOKED);
            }
        } catch (TokenValidationException e) {
            log.error(e);
            return new CheckRevocationResponse(ValidationStatus.INVALID);
        }
        return new CheckRevocationResponse(ValidationStatus.VALID);
    }

}
