package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Used to issue tokens.
 *
 * @author Mikołaj Dobski (PSNC)
 */
@Component
public class TokenIssuer {

    private static Log log = LogFactory.getLog(TokenIssuer.class);
    // TODO R3 create a CRUD for this
    public Map<String, String> federatedMappingRules = new HashMap<>();
    // AAM configuration
    private String deploymentId = "";
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;
    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;
    private CertificationAuthorityHelper certificationAuthorityHelper;
    private PlatformRepository platformRepository;


    @Autowired
    public TokenIssuer(CertificationAuthorityHelper certificationAuthorityHelper,
                       PlatformRepository platformRepository) {

        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.platformRepository = platformRepository;
    }

    /**
     * TODO R3 needs client id, to know which SPK to include
     *
     * @param user for which to issue to token
     * @return home token issued for given user
     * @throws JWTCreationException on error
     */
    public Token getHomeToken(User user)
            throws JWTCreationException {
        try {
            Map<String, String> attributes = new HashMap<>();

            switch (deploymentType) {
                case CORE:
                    switch (user.getRole()) {
                        case USER:
                            attributes.put(CoreAttributes.ROLE.toString(), UserRole.USER.toString());
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
                            .getPublicKey().getEncoded(), deploymentType, tokenValidity, deploymentId,
                    certificationAuthorityHelper
                            .getAAMPublicKey(), certificationAuthorityHelper.getAAMPrivateKey()));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

    public Token getForeignToken(String foreignToken)
            throws JWTCreationException {
        try {
            JWTClaims claims = JWTEngine.getClaimsFromToken(foreignToken);
            // TODO R3 Attribute Mapping Function
            Map<String, String> federatedAttributes = new HashMap<>();

            // disabling federated token issuing when the mapping rule is empty
            if (federatedMappingRules.isEmpty())
                throw new SecurityMisconfigurationException("AAM has no federation rules defined");
            return new Token(
                    JWTEngine.generateJWTToken(claims.getIss(), federatedAttributes, Base64.getDecoder().decode(claims
                                    .getIpk()), deploymentType, tokenValidity, deploymentId,
                            certificationAuthorityHelper
                                    .getAAMPublicKey(),
                            certificationAuthorityHelper.getAAMPrivateKey()));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

    public void getGuestToken() {
        // TODO @Jakub implement and return a guest token
    }
}
