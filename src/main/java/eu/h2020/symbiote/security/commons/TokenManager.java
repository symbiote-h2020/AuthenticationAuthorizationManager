package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.custom.*;
import eu.h2020.symbiote.security.interfaces.ICoreServices;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.RevokedTokensRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.*;

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
    public Map<String, String> federatedMappingRules = new HashMap<>();
    private RestTemplate restTemplate = new RestTemplate();
    private ICoreServices coreServices;
    private RegistrationManager regManager;
    private PlatformRepository platformRepository;
    private String deploymentId = "";
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;
    private RevokedKeysRepository revokedKeysRepository;
    private RevokedTokensRepository revokedTokensRepository;
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;

    @Autowired
    public TokenManager(ICoreServices coreServices, RegistrationManager regManager,
                        PlatformRepository platformRepository, RevokedKeysRepository revokedKeysRepository,
                        RevokedTokensRepository revokedTokensRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.coreServices = coreServices;
        this.regManager = regManager;
        this.deploymentId = regManager.getAAMInstanceIdentifier();
        this.deploymentType = regManager.getDeploymentType();
        this.platformRepository = platformRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.revokedTokensRepository = revokedTokensRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
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

            // disabling federated token issuing when the mapping rule is empty
            if (federatedMappingRules.isEmpty())
                throw new SecurityMisconfigurationException("AAM has no federation rules defined");
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

    public ValidationStatus validate(String tokenString, String certificateString) {
        try {
            // basic validation (signature and exp)
            ValidationStatus validationStatus = JWTEngine.validateTokenString(tokenString);
            if (validationStatus != ValidationStatus.VALID) {
                return validationStatus;
            }

            Claims claims = JWTEngine.getClaims(tokenString);
            String spk = claims.get("spk").toString();
            String ipk = claims.get("ipk").toString();

            // flow for Platform AAM
            if (deploymentType != IssuingAuthorityType.CORE) {
                if (!deploymentId.equals(claims.getIssuer())) {
                    // relay validation to issuer
                    return validateFederatedToken(tokenString, certificateString);
                }

                // check IPK is not equal to current AAM PK
                if (!Base64.getEncoder().encodeToString(
                        regManager.getAAMCertificate().getPublicKey().getEncoded()).equals(ipk)) {
                    return ValidationStatus.REVOKED_IPK;
                }

                // check if issuer certificate is not expired
                if (certificateExpired(regManager.getAAMCertificate())) {
                    return ValidationStatus.EXPIRED_ISSUER_CERTIFICATE;
                }

                // todo R3 possible validation of revoked IPK from CoreAAM - check if IPK was not revoked in the core
                // possibly throw runtime exception so that AAM crashes as it is no more valid
            } else {
                // check if IPK is in the revoked set
                if (revokedKeysRepository.exists(claims.getIssuer()) &&
                        revokedKeysRepository.findOne(claims.getIssuer()).getRevokedKeysSet().contains(ipk)) {
                    return ValidationStatus.REVOKED_IPK;
                }
                // check if core is not an issuer
                if (!deploymentId.equals(claims.getIssuer())) {
                    // relay validation to issuer
                    return validateFederatedToken(tokenString, certificateString);
                }

                // check if issuer certificate is not expired
                if (certificateExpired(regManager.getAAMCertificate()))
                    return ValidationStatus.EXPIRED_ISSUER_CERTIFICATE;

                // check if it is core but with not valid PK
                if (!Base64.getEncoder().encodeToString(
                        regManager.getAAMCertificate().getPublicKey().getEncoded()).equals(ipk)) {
                    return ValidationStatus.INVALID_TRUST_CHAIN;
                }
            }
            // check revoked JTI
            if (revokedTokensRepository.exists(claims.getId())) {
                return ValidationStatus.REVOKED_TOKEN;
            }

            // check if SPK is is in the revoked set
            if (revokedKeysRepository.exists(claims.getSubject()) &&
                    revokedKeysRepository.findOne(claims.getSubject()).getRevokedKeysSet().contains(spk)) {
                return ValidationStatus.REVOKED_SPK;
            }

            if (certificateExpired(userRepository.findOne(claims.getSubject()).getCertificate().getX509())) {
                return ValidationStatus.EXPIRED_SUBJECT_CERTIFICATE;
            }

        } catch (ValidationException | IOException | CertificateException | NoSuchAlgorithmException |
                KeyStoreException | NoSuchProviderException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }
        return ValidationStatus.VALID;
    }

    public ValidationStatus validateFederatedToken(String tokenString, String certificateString) throws CertificateException,
            NullPointerException, ValidationException {
        // if can access certificate, do not have to make a relay
        if (!certificateString.isEmpty()) {
            // TODO certificate validation and appropriate status return
            // if certificate is not valid return
            return ValidationStatus.INVALID_TRUST_CHAIN;
        }
        Map<String, AAM> aams = new HashMap<>();
        for (AAM aam : coreServices.getAvailableAAMs().getBody())
            aams.put(aam.getAamInstanceId(), aam);
        Claims claims = JWTEngine.getClaims(tokenString);
        String issuer = claims.getIssuer();
        // Core does not know such an issuer and therefore this might be a forfeit
        if (!aams.containsKey(issuer))
            return ValidationStatus.INVALID_TRUST_CHAIN;
        AAM issuerAAM = aams.get(issuer);
        String aamAddress = issuerAAM.getAamAddress();
        PublicKey publicKey = issuerAAM.getCertificate().getX509().getPublicKey();

        // check IPK
        if (!Base64.getEncoder().encodeToString(publicKey.getEncoded()).equals(claims.get("ipk"))) {
            return ValidationStatus.REVOKED_IPK;
        }

        // rest check revocation
        // preparing request
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(AAMConstants.TOKEN_HEADER_NAME, tokenString);
        HttpEntity<String> entity = new HttpEntity<>(null, httpHeaders);
        // checking token revocation with proper AAM
        try {
            ResponseEntity<CheckRevocationResponse> status = restTemplate.postForEntity(
                    aamAddress + AAMConstants.AAM_VALIDATE,
                    entity, CheckRevocationResponse.class);
            if (status.getStatusCode().is2xxSuccessful())
                return ValidationStatus.valueOf(status.getBody().getStatus());
        } catch (Exception e) {
            log.error(e);
        }
        return ValidationStatus.WRONG_AAM;
    }

    private boolean certificateExpired(X509Certificate certificate) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        try {
            certificate.checkValidity(new Date());
        } catch (CertificateExpiredException e) {
            log.info(e);
            return true;
        }
        return false;
    }

    public void revoke(Credentials credentials, Certificate certificate)
            throws CertificateException, WrongCredentialsException, NotExistingUserException {
        // user public key revocation
        User user = userRepository.findOne(credentials.getUsername());
        if (user == null) {
            throw new NotExistingUserException();
        }
        if (passwordEncoder.matches(credentials.getPassword(), user.getPasswordEncrypted())) {
            if (user.getCertificate().getCertificateString().equals(certificate.getCertificateString())) {
                SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(user.getUsername());
                Set<String> keySet = (subjectsRevokedKeys == null) ? new HashSet<>() : subjectsRevokedKeys.getRevokedKeysSet();
                keySet.add(Base64.getEncoder().encodeToString(
                        certificate.getX509().getPublicKey().getEncoded()));
                // adding key to revoked repository
                revokedKeysRepository.save(new SubjectsRevokedKeys(user.getUsername(), keySet));
            } else {
                throw new CertificateException();
            }
        } else {
            throw new WrongCredentialsException();
        }
    }

    public void revoke(Credentials credentials, Token token) throws CertificateException, WrongCredentialsException,
            NotExistingUserException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            KeyStoreException, IOException, ValidationException {
        if (validate(token.getToken(), "") != ValidationStatus.VALID)
            throw new ValidationException("Invalid token");
        // user token revocation
        User user = userRepository.findOne(credentials.getUsername());
        if (user != null) {
            if (passwordEncoder.matches(credentials.getPassword(), user.getPasswordEncrypted())) {
                // user
                if (Base64.getEncoder().encodeToString(user.getCertificate().getX509().getPublicKey().getEncoded()).equals(token.getClaims().get("spk"))) {
                    revokedTokensRepository.save(token);
                    return;
                }
                // platform owner
                Platform platform = platformRepository.findByPlatformOwner(user);
                if (platform != null && Base64.getEncoder().encodeToString(
                        platform.getPlatformAAMCertificate().getX509().getPublicKey().getEncoded())
                        .equals(token.getClaims().get("ipk").toString())) {
                    revokedTokensRepository.save(token);
                    return;
                }
                throw new ValidationException("You have no rights to this token");
            } else {
                throw new WrongCredentialsException();
            }
        } else {
            throw new NotExistingUserException();
        }
    }

}
