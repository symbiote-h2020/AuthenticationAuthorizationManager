package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import eu.h2020.symbiote.security.repositories.FederationsRepository;
import eu.h2020.symbiote.security.repositories.LocalUsersAttributesRepository;
import eu.h2020.symbiote.security.repositories.entities.Attribute;
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
import java.util.stream.Collectors;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.FIELDS_DELIMITER;

/**
 * Used to issue tokens.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class TokenIssuer {

    private static Log log = LogFactory.getLog(TokenIssuer.class);
    private static SecureRandom random = new SecureRandom();
    // AAM configuration
    private final String deploymentId;
    private final IssuingAuthorityType deploymentType;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final LocalUsersAttributesRepository localUsersAttributesRepository;
    private final FederationsRepository federationsRepository;
    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;
    private KeyPair guestKeyPair;

    @Autowired
    public TokenIssuer(CertificationAuthorityHelper certificationAuthorityHelper,
                       LocalUsersAttributesRepository localUsersAttributesRepository,
                       FederationsRepository federationsRepository) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.localUsersAttributesRepository = localUsersAttributesRepository;
        this.federationsRepository = federationsRepository;
    }

    public static String buildAuthorizationToken(String subject,
                                                 Map<String, String> attributes,
                                                 byte[] subjectPublicKey,
                                                 Token.Type tokenType,
                                                 Long tokenValidity,
                                                 String issuer,
                                                 PublicKey issuerPublicKey,
                                                 PrivateKey issuerPrivateKey) {
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
    public Token getHomeToken(User user, String sub, PublicKey issuerPublicKey)
            throws JWTCreationException {
        try {
            Map<String, String> attributes = new HashMap<>();
            if (deploymentType.equals(IssuingAuthorityType.NULL))
                throw new JWTCreationException(JWTCreationException.MISCONFIGURED_AAM_DEPLOYMENT_TYPE);
            //adding local user's attributes
            for (Attribute entry : localUsersAttributesRepository.findAll()) {
                attributes.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + entry.getKey(), entry.getValue());
            }
            //adding particular user's attributes
            for (Map.Entry<String, String> entry : user.getAttributes().entrySet()) {
                attributes.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + entry.getKey(), entry.getValue());
            }
            //checking username - if empty we are dealing with local Component and subject shouldn't contain admins name
            String subject;
            if (user.getUsername().isEmpty()) {
                subject = sub;
            } else {
                subject = user.getUsername() + FIELDS_DELIMITER + sub;
            }

            return new Token(buildAuthorizationToken(
                    // HOME SUB: username@clientIdentifier
                    subject,
                    attributes,
                    issuerPublicKey.getEncoded(),
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
     * @throws JWTCreationException throwed when error during creation of the token occurs
     */
    public Token getForeignToken(Token remoteHomeToken)
            throws JWTCreationException, ValidationException {

        // if one has account in the AAM then should not request a foreign token
        if (remoteHomeToken.getClaims().getIssuer().equals(deploymentId)) {
            log.info(ValidationException.ISSUING_FOREIGN_TOKEN_ERROR);
            throw new ValidationException(ValidationException.ISSUING_FOREIGN_TOKEN_ERROR);
        }

        try {
            JWTClaims claims = JWTEngine.getClaimsFromToken(remoteHomeToken.toString());
            HashMap<String, String> foreignAttributes = new HashMap<>();
            // disabling foreign token issuing when the mapping rule is empty
            if (federationsRepository.findAll().isEmpty())
                throw new SecurityMisconfigurationException(SecurityMisconfigurationException.AAM_HAS_NO_FEDERATIONS_DEFINED);
            int i = 1;


            for (Federation federation : federationsRepository.findAll()) {
                if (federation.getMembers().stream()
                        .map(FederationMember::getPlatformId)
                        .collect(Collectors.toSet())
                        .contains(claims.getIss())) {
                    foreignAttributes.put(SecurityConstants.FEDERATION_CLAIM_KEY_PREFIX + i, federation.getId());
                    i++;
                }
            }
            return new Token(buildAuthorizationToken(
                    // FOREIGN SUB: username@clientIdentifier@homeAAMInstanceIdentifier@originHomeTokenJTI
                    claims.getSub() + FIELDS_DELIMITER + claims.getIss() + FIELDS_DELIMITER + claims.getJti(),
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
