package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.CoreAttributes;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
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

import java.security.KeyPair;
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
 * @author Jakub Toczek (PSNC)
 */
@Component
public class TokenIssuer {

    private static final String ISSUING_FOREIGN_TOKEN_ERROR = "Someone tried issuing a foreign token using a home token";
    private static Log log = LogFactory.getLog(TokenIssuer.class);
    private static SecureRandom random = new SecureRandom();
    // TODO R3 create a CRUD for this
    public Map<String, String> foreignMappingRules = new HashMap<>();
    // AAM configuration
    private String deploymentId = "";
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;
    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;
    private CertificationAuthorityHelper certificationAuthorityHelper;
    private PlatformRepository platformRepository;
    private KeyPair guestKeyPair;

    @Autowired
    public TokenIssuer(CertificationAuthorityHelper certificationAuthorityHelper,
                       PlatformRepository platformRepository) {

        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.platformRepository = platformRepository;
    }

    public static String buildAuthorizationToken(String subject, Map<String, String> attributes, byte[] subjectPublicKey,
                                                 Token.Type tokenType, Long tokenValidity, String
                                                         issuer, PublicKey issuerPublicKey, PrivateKey issuerPrivateKey) {
        ECDSAHelper.enableECDSAProvider();

        String jti = String.valueOf(random.nextInt());
        Map<String, Object> claimsMap = new HashMap<>();

        // Insert AAM Public Key
        claimsMap.put("ipk", Base64.getEncoder().encodeToString(issuerPublicKey.getEncoded()));

        //Insert issuee Public Key
        claimsMap.put("spk", Base64.getEncoder().encodeToString(subjectPublicKey));

        //Add symbIoTe related attributes to token
        if (attributes != null && !attributes.isEmpty()) {
            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                claimsMap.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + entry.getKey(), entry.getValue());
            }
        }

        //Insert token type
        claimsMap.put(SecurityConstants.CLAIM_NAME_TOKEN_TYPE, tokenType);

        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setClaims(claimsMap);
        jwtBuilder.setId(jti);
        jwtBuilder.setIssuer(issuer);
        jwtBuilder.setSubject(subject);
        jwtBuilder.setIssuedAt(new Date());
        jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + tokenValidity));
        jwtBuilder.signWith(SignatureAlgorithm.ES256, issuerPrivateKey);

        return jwtBuilder.compact();
    }

    /**
     * @param user for which to issue to token
     * @return home token issued for given user
     * @throws JWTCreationException on error
     */
    public Token getHomeToken(User user, String clientId)
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
            return new Token(buildAuthorizationToken(
                    // HOME SUB: username@clientIdentifier
                    user.getUsername() + "@" + clientId,
                    attributes,
                    user.getClientCertificates().get(clientId).getX509().getPublicKey().getEncoded(),
                    Token.Type.HOME,
                    tokenValidity,
                    deploymentId,
                    certificationAuthorityHelper.getAAMPublicKey(),
                    certificationAuthorityHelper.getAAMPrivateKey()
            ));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

    /**
     * @param remoteHomeToken from which needed information and attributes are gathered and mapped
     * @return foreignToken issued for given user
     * @throws JWTCreationException
     */
    public Token getForeignToken(Token remoteHomeToken)
            throws JWTCreationException, ValidationException {

        // if one has account in the AAM then should not request a foreign token
        if (remoteHomeToken.getClaims().getIssuer().equals(deploymentId)) {
            log.info(ISSUING_FOREIGN_TOKEN_ERROR);
            throw new ValidationException(ISSUING_FOREIGN_TOKEN_ERROR);
        }

        try {
            JWTClaims claims = JWTEngine.getClaimsFromToken(remoteHomeToken.toString());

            // TODO R3 Attribute Mapping Function
            Map<String, String> foreignAttributes = new HashMap<>();

            // disabling foreign token issuing when the mapping rule is empty
            if (foreignMappingRules.isEmpty())
                throw new SecurityMisconfigurationException("AAM has no foreign rules defined");
            return new Token(buildAuthorizationToken(
                    // FOREIGN SUB: username@clientIdentifier@homeAAMInstanceIdentifier
                    claims.getSub() + "@" + claims.getIss(),
                    foreignAttributes,
                    Base64.getDecoder().decode(claims.getSpk()),
                    Token.Type.FOREIGN,
                    tokenValidity,
                    deploymentId,
                    certificationAuthorityHelper.getAAMPublicKey(),
                    certificationAuthorityHelper.getAAMPrivateKey()));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

    /**
     * Function creating GuestToken, all with the same keyPair and empty attributes list.
     *
     * @return Token - GuestToken
     * @throws JWTCreationException - in case of fail in building GuestToken
     */
    public Token getGuestToken() throws JWTCreationException {
        try {
            if (this.guestKeyPair == null) {
                this.guestKeyPair = CryptoHelper.createKeyPair();
            }
            return new Token(buildAuthorizationToken(
                    SecurityConstants.GUEST_NAME,
                    new HashMap<>(),
                    this.guestKeyPair.getPublic().getEncoded(),
                    Token.Type.GUEST,
                    tokenValidity,
                    deploymentId,
                    certificationAuthorityHelper.getAAMPublicKey(),
                    certificationAuthorityHelper.getAAMPrivateKey()));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

}
