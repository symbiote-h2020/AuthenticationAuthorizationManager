package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.aam.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.aam.TokenValidationException;
import eu.h2020.symbiote.security.interfaces.ICoreServices;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.RevokedTokensRepository;
import eu.h2020.symbiote.security.services.TokenService;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import io.jsonwebtoken.Claims;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class for managing operations (creation, verification checking, etc.) on
 * tokens in token related service ({@link TokenService}).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Piotr Kicki (PSNC)
 */
@Component
public class TokenManager {

    private static Log log = LogFactory.getLog(TokenManager.class);
    private RestTemplate restTemplate = new RestTemplate();
    private ICoreServices coreServices;
    private RegistrationManager regManager;
    private PlatformRepository platformRepository;
    private String deploymentId = "";
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;
    private RevokedKeysRepository revokedKeysRepository;
    private RevokedTokensRepository revokedTokensRepository;
    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;

    @Autowired
    public TokenManager(ICoreServices coreServices, RegistrationManager regManager, PlatformRepository platformRepository, RevokedKeysRepository revokedKeysRepository, RevokedTokensRepository revokedTokensRepository) {
        this.coreServices = coreServices;
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
                    JWTEngine.generateJWTToken(claims.getIss(), federatedAttributes, Base64.getDecoder().decode(claims
                                    .getIpk()), deploymentType, tokenValidity, deploymentId, regManager
                                    .getAAMPublicKey(),
                            regManager.getAAMPrivateKey()));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

    public CheckRevocationResponse validate(String tokenString) {
        try {
            // basic validation (signature and exp)
            ValidationStatus validationStatus = JWTEngine.validateTokenString(tokenString);
            if (validationStatus != ValidationStatus.VALID) {
                return new CheckRevocationResponse(validationStatus);
            }

            Claims claims = JWTEngine.getClaims(tokenString);
            String spk = claims.get("spk").toString();
            String ipk = claims.get("ipk").toString();
            // flow for Platform AAM
            if (deploymentType != IssuingAuthorityType.CORE) {
                if (!deploymentId.equals(claims.getIssuer())) {
                    // todo think of better status for foreign token which we should not validate (maybe exception?)
                    // relay validation to issuer
                    return relayedValidation(tokenString, claims.getIssuer());
                }
                // check IPK is not equal to current AAM PK
                if (!Base64.getEncoder().encodeToString(
                        regManager.getAAMCertificate().getPublicKey().getEncoded()).equals(ipk)) {
                    return new CheckRevocationResponse(ValidationStatus.REVOKED);
                }
                // todo R3 possible validation of revoked IPK from CoreAAM - check if IPK was not revoked in the core
            } else {
                // check if IPK is in the revoked set
                if (revokedKeysRepository.exists(claims.getIssuer()) &&
                        revokedKeysRepository.findOne(claims.getIssuer()).getRevokedKeysSet().contains(ipk)) {
                    return new CheckRevocationResponse(ValidationStatus.REVOKED);
                }

                if (!deploymentId.equals(claims.getIssuer())) {
                    // relay validation to issuer
                    return relayedValidation(tokenString, claims.getIssuer());
                }
            }
            // check revoked JTI
            if (revokedTokensRepository.exists(claims.getId())) {
                return new CheckRevocationResponse(ValidationStatus.REVOKED);
            }

            // check if SPK is is in the revoked set
            if (revokedKeysRepository.exists(claims.getSubject()) &&
                    revokedKeysRepository.findOne(claims.getSubject()).getRevokedKeysSet().contains(spk)) {
                return new CheckRevocationResponse(ValidationStatus.REVOKED);
            }
        } catch (TokenValidationException | IOException | CertificateException | NoSuchAlgorithmException |
                KeyStoreException | NoSuchProviderException e) {
            log.error(e);
            return new CheckRevocationResponse(ValidationStatus.INVALID);
        }
        return new CheckRevocationResponse(ValidationStatus.VALID);
    }

    private CheckRevocationResponse relayedValidation(String tokenString, String issuer) {
        List<AAM> listAAM = coreServices.getAvailableAAMs().getBody();
        String aamAdress = null;
        for (AAM aam : listAAM) {
            if (aam.getAamInstanceId().equals(issuer)) {
                aamAdress = aam.getAamAddress();
            }
        }
        if (aamAdress != null) {
            // rest check revocation
            // preparing request

            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.add(AAMConstants.TOKEN_HEADER_NAME, tokenString);
            HttpEntity<String> entity = new HttpEntity<>(null, httpHeaders);
            // checking token revocation with proper AAM
            ResponseEntity<CheckRevocationResponse> status = restTemplate.postForEntity(
                    aamAdress + AAMConstants.AAM_CHECK_HOME_TOKEN_REVOCATION,
                    entity, CheckRevocationResponse.class);
            return status.getBody();
        } else {
            // todo change returned status to meet sh3.0 symbIoTelibs requirements
            return new CheckRevocationResponse(ValidationStatus.INVALID);
        }
    }

}
