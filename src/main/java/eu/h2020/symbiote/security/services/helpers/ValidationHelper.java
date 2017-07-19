package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.interfaces.IAAMServices;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.RevokedTokensRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
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
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Used to validate given credentials againts data in the AAMs
 * <p>
 * TODO @Mikołaj review and refactor
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Piotr Kicki (PSNC)
 */
@Component
public class ValidationHelper {

    private static Log log = LogFactory.getLog(ValidationHelper.class);

    // AAM configuration
    private String deploymentId = "";
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;
    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;
    // dependencies
    private RestTemplate restTemplate = new RestTemplate();
    private IAAMServices coreServices;
    private CertificationAuthorityHelper certificationAuthorityHelper;
    private RevokedKeysRepository revokedKeysRepository;
    private RevokedTokensRepository revokedTokensRepository;
    private UserRepository userRepository;

    @Autowired
    public ValidationHelper(IAAMServices coreServices, CertificationAuthorityHelper certificationAuthorityHelper,
                            RevokedKeysRepository revokedKeysRepository,
                            RevokedTokensRepository revokedTokensRepository, UserRepository userRepository) {
        this.coreServices = coreServices;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.revokedKeysRepository = revokedKeysRepository;
        this.revokedTokensRepository = revokedTokensRepository;
        this.userRepository = userRepository;
    }

    //TODO getting certificates
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
                    return validateForeignToken(tokenString, certificateString);
                }

                // check IPK is not equal to current AAM PK
                if (!Base64.getEncoder().encodeToString(
                        certificationAuthorityHelper.getAAMCertificate().getPublicKey().getEncoded()).equals(ipk)) {
                    return ValidationStatus.REVOKED_IPK;
                }

                // check if issuer certificate is not expired
                if (isExpired(certificationAuthorityHelper.getAAMCertificate())) {
                    return ValidationStatus.EXPIRED_ISSUER_CERTIFICATE;
                }
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
                    return validateForeignToken(tokenString, certificateString);
                }

                // check if issuer certificate is not expired
                if (isExpired(certificationAuthorityHelper.getAAMCertificate()))
                    return ValidationStatus.EXPIRED_ISSUER_CERTIFICATE;

                // check if it is core but with not valid PK
                if (!Base64.getEncoder().encodeToString(
                        certificationAuthorityHelper.getAAMCertificate().getPublicKey().getEncoded()).equals(ipk)) {
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

            // check if subject certificate is valid
            if (isExpired(userRepository.findOne(claims.getSubject()).getClientCertificates().entrySet().iterator()
                    .next().getValue().getX509())) {
                return ValidationStatus.EXPIRED_SUBJECT_CERTIFICATE;
            }

        } catch (ValidationException | IOException | CertificateException | NoSuchAlgorithmException |
                KeyStoreException | NoSuchProviderException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }
        return ValidationStatus.VALID;
    }

    public ValidationStatus validateForeignToken(String tokenString, String certificateString) throws
            CertificateException,
            NullPointerException, ValidationException, NoSuchAlgorithmException, NoSuchProviderException,
            KeyStoreException, IOException {
        // if the certificate is not empty, then check the trust chain
        if (!certificateString.isEmpty() && !isTrusted(certificationAuthorityHelper
                .getAAMCertificate(), certificateString))
            return ValidationStatus.INVALID_TRUST_CHAIN;
        // TODO check if AAM is online or is configured to allow 'offline' trust chain only validation

        Map<String, AAM> aams = new HashMap<>();
        for (AAM aam : coreServices.getAvailableAAMs().values())
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
        httpHeaders.add(SecurityConstants.TOKEN_HEADER_NAME, tokenString);
        HttpEntity<String> entity = new HttpEntity<>(null, httpHeaders);
        // checking token revocation with proper AAM
        try {
            ResponseEntity<ValidationStatus> status = restTemplate.postForEntity(
                    aamAddress + SecurityConstants.AAM_VALIDATE,
                    entity, ValidationStatus.class);
            return status.getBody();
        } catch (Exception e) {
            log.error(e);
            // when there is problem with request
            return ValidationStatus.WRONG_AAM;
        }
    }

    private boolean isExpired(X509Certificate certificate) {
        try {
            certificate.checkValidity(new Date());
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            log.info(e);
            return true;
        }
        return false;
    }

    /**
     * TODO R3 @Daniele
     * implement method to validate trust chain
     */
    private boolean isTrusted(X509Certificate AAMCertificate, String certificateString) {
        return true;
    }
}
