package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.CoreAttributes;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
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
    private static SecureRandom random = new SecureRandom();
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

    public static String generateJWTToken(String userId, Map<String, String> attributes, byte[] userPublicKey,
                                          IssuingAuthorityType deploymentType, Long tokenValidity, String
                                                  deploymentID, PublicKey aamPublicKey, PrivateKey aamPrivateKey)
            throws JWTCreationException {
        ECDSAHelper.enableECDSAProvider();

        String jti = String.valueOf(random.nextInt());
        Map<String, Object> claimsMap = new HashMap<>();

        try {
            // Insert AAM Public Key
            claimsMap.put("ipk", org.apache.commons.codec.binary.Base64.encodeBase64String(aamPublicKey.getEncoded()));

            //Insert issuee Public Key
            claimsMap.put("spk", org.apache.commons.codec.binary.Base64.encodeBase64String(userPublicKey));

            //Add symbIoTe related attributes to token
            if (attributes != null && !attributes.isEmpty()) {
                for (Map.Entry<String, String> entry : attributes.entrySet()) {
                    claimsMap.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + entry.getKey(), entry.getValue());
                }
            }

            //Insert token type based on AAM deployment type (Core or Platform)
            switch (deploymentType) {
                case CORE:
                    claimsMap.put(SecurityConstants.CLAIM_NAME_TOKEN_TYPE, IssuingAuthorityType.CORE);
                    break;
                case PLATFORM:
                    claimsMap.put(SecurityConstants.CLAIM_NAME_TOKEN_TYPE, IssuingAuthorityType.PLATFORM);
                    break;
                case NULL:
                    throw new JWTCreationException("uninitialized deployment type, must be CORE or PLATFORM");
            }

            JwtBuilder jwtBuilder = Jwts.builder();
            jwtBuilder.setClaims(claimsMap);
            jwtBuilder.setId(jti);
            jwtBuilder.setIssuer(deploymentID);
            jwtBuilder.setSubject(userId);
            jwtBuilder.setIssuedAt(new Date());
            jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + tokenValidity));
            jwtBuilder.signWith(SignatureAlgorithm.ES256, aamPrivateKey);

            return jwtBuilder.compact();
        } catch (Exception e) {
            String message = "JWT creation error";
            log.error(message, e);
            throw new JWTCreationException(message, e);
        }
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
        System.out.println("MARKER3");
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
            return new Token(generateJWTToken(user.getUsername(), attributes, user.getClientCertificates().entrySet().iterator()
                            .next().getValue().getX509().getPublicKey().getEncoded(), deploymentType, tokenValidity, deploymentId,
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
                    generateJWTToken(claims.getIss(), federatedAttributes, Base64.getDecoder().decode(claims
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
