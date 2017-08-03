package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.RevokedTokensRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.services.AAMServices;
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
import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * Used to validate given credentials against data in the AAMs
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

    @Value("${aam.deployment.validation.allow-offline}")
    private boolean isOfflineEnough;

    // dependencies
    private RestTemplate restTemplate = new RestTemplate();
    private CertificationAuthorityHelper certificationAuthorityHelper;
    private RevokedKeysRepository revokedKeysRepository;
    private RevokedTokensRepository revokedTokensRepository;
    private UserRepository userRepository;
    private AAMServices aamServices;

    @Autowired
    public ValidationHelper(CertificationAuthorityHelper certificationAuthorityHelper,
                            RevokedKeysRepository revokedKeysRepository,
                            RevokedTokensRepository revokedTokensRepository, UserRepository userRepository, AAMServices aamServices) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.revokedKeysRepository = revokedKeysRepository;
        this.revokedTokensRepository = revokedTokensRepository;
        this.userRepository = userRepository;
        this.aamServices = aamServices;
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

    public ValidationStatus validateForeignToken(String tokenString, String clientCertificateChainPEMsString) throws
            CertificateException,
            ValidationException, NoSuchAlgorithmException, NoSuchProviderException,
            KeyStoreException, IOException {
        // if the certificate is not empty, then check the trust chain
        if (!clientCertificateChainPEMsString.isEmpty()) {
            try {
                // TODO Daniele please refactor this awful code by Mikołaj :)
                // split it into intermediate cert and app cert
                String certEnd = "-----END CERTIFICATE-----\n";
                int splitIndex = clientCertificateChainPEMsString.indexOf(certEnd) + certEnd.length();
                String signingAAMCert = clientCertificateChainPEMsString.substring(0, splitIndex);
                String appCert = clientCertificateChainPEMsString.substring(splitIndex);
                // reject on failed trust chain
                if (!isTrusted(CryptoHelper.convertPEMToX509(signingAAMCert), appCert))
                    return ValidationStatus.INVALID_TRUST_CHAIN;
                // end procedure if offline validation is enough
                if (isOfflineEnough)
                    return ValidationStatus.VALID;
            } catch (NullPointerException npe) {
                log.error("Problem with parsing the given PEMs string");
                return ValidationStatus.INVALID_TRUST_CHAIN;
            }
        }

        // resolving available AAMs in search of the token issuer
        Map<String, AAM> availableAAMs = aamServices.getAvailableAAMs();
        Claims claims = JWTEngine.getClaims(tokenString);
        String issuer = claims.getIssuer();
        // Core does not know such an issuer and therefore this might be a forfeit
        if (!availableAAMs.containsKey(issuer))
            return ValidationStatus.INVALID_TRUST_CHAIN;
        AAM issuerAAM = availableAAMs.get(issuer);
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

    public boolean isTrusted(X509Certificate signingAAMCertificate, String applicationCertificateString) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        X509Certificate rootCertificate = certificationAuthorityHelper.getRootCACertificate();

        // convert application certificate to X509
        X509Certificate applicationCertificate = CryptoHelper.convertPEMToX509(applicationCertificateString);

        // Create the selector that specifies the starting certificate
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(applicationCertificate);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
        TrustAnchor trustAnchor = new TrustAnchor(rootCertificate, null);
        trustAnchors.add(trustAnchor);

        // List of intermediate certificates
        List<X509Certificate> intermediateCertificates = new ArrayList<X509Certificate>();
        intermediateCertificates.add(signingAAMCertificate);
        intermediateCertificates.add(applicationCertificate);

        /*
         * If build() returns successfully, the certificate is valid. More details
         * about the valid path can be obtained through the PKIXCertPathBuilderResult.
         * If no valid path can be found, a CertPathBuilderException is thrown.
         */
        try {
            // Create the selector that specifies the starting certificate
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, target);
            // Disable CRL checks (this is done manually as additional step)
            params.setRevocationEnabled(false);

            // Specify a list of intermediate certificates
            CertStore intermediateCertStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(intermediateCertificates), "BC");
            params.addCertStore(intermediateCertStore);

            // Build and verify the certification chain
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(params);

            // log.info(result.getCertPath().toString());

            return true;

        } catch (CertPathBuilderException | InvalidAlgorithmParameterException e) {
            log.info(e);
            return false;
        }
    }
}
