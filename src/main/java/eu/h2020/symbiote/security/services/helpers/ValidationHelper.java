package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.*;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
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

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

import eu.h2020.symbiote.security.commons.Certificate;


/**
 * Used to validate given credentials against data in the AAMs
 * <p>
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
    private final String deploymentId;
    private final IssuingAuthorityType deploymentType;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final RevokedKeysRepository revokedKeysRepository;
    private final RevokedTokensRepository revokedTokensRepository;
    private final FederationRulesRepository federationRulesRepository;
    private final UserRepository userRepository;
    private final PlatformRepository platformRepository;
    private final ComponentCertificatesRepository componentCertificatesRepository;
    private final AAMServices aamServices;

    // usable
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;
    @Value("${aam.deployment.validation.allow-offline}")
    private boolean isOfflineEnough;

    @Autowired
    public ValidationHelper(CertificationAuthorityHelper certificationAuthorityHelper,
                            RevokedKeysRepository revokedKeysRepository,
                            RevokedTokensRepository revokedTokensRepository, FederationRulesRepository federationRulesRepository, UserRepository userRepository, PlatformRepository platformRepository, ComponentCertificatesRepository componentCertificatesRepository, AAMServices aamServices) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.revokedKeysRepository = revokedKeysRepository;
        this.revokedTokensRepository = revokedTokensRepository;
        this.federationRulesRepository = federationRulesRepository;
        this.userRepository = userRepository;
        this.platformRepository = platformRepository;
        this.componentCertificatesRepository = componentCertificatesRepository;
        this.aamServices = aamServices;
    }

    public ValidationStatus validate(String token, String clientCertificate, String clientCertificateSigningAAMCertificate, String foreignTokenIssuingAAMCertificate) {
        try {
            // basic validation (signature and exp)
            ValidationStatus validationStatus = JWTEngine.validateTokenString(token);
            if (validationStatus != ValidationStatus.VALID) {
                return validationStatus;
            }

            Claims claims = JWTEngine.getClaims(token);
            String spk = claims.get("spk").toString();
            String ipk = claims.get("ipk").toString();

            // flow for Platform AAM
            if (deploymentType != IssuingAuthorityType.CORE) {
                if (!deploymentId.equals(claims.getIssuer())) {
                    // relay validation to issuer
                    return validateRemotelyIssuedToken(token, clientCertificate, clientCertificateSigningAAMCertificate, foreignTokenIssuingAAMCertificate);
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
                    return validateRemotelyIssuedToken(token, clientCertificate, clientCertificateSigningAAMCertificate, foreignTokenIssuingAAMCertificate);
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

            String userFromToken = claims.getSubject().split("@")[0];
            String clientId = claims.getSubject().split("@")[1];


            // check if SPK is is in the revoked set for user token
            if (claims.getSubject().split("@").length == 2)
                if (revokedKeysRepository.exists(userFromToken) &&
                        revokedKeysRepository.findOne(userFromToken).getRevokedKeysSet().contains(spk)) {
                    return ValidationStatus.REVOKED_SPK;
                }

            // check if SPK is is in the revoked set for component token
            if (claims.getSubject().split("@").length == 3)
                if (revokedKeysRepository.exists(clientId) && revokedKeysRepository.findOne(clientId).getRevokedKeysSet().contains(spk)) {
                    return ValidationStatus.REVOKED_SPK;
                }


            // check if subject certificate is valid & matching the token SPK
            if (claims.get("ttyp").equals(Token.Type.HOME.toString())) {
                if (claims.getSubject().split("@").length == 3) {
                    // components use case
                    String platformId = claims.getSubject().split("@")[2];
                    Certificate componentCertificate = null;

                    if (platformId.equals(SecurityConstants.CORE_AAM_INSTANCE_ID)) {
                        // core component case
                        ComponentCertificate coreComponentCertificate = componentCertificatesRepository.findOne(clientId);
                        if (coreComponentCertificate != null)
                            componentCertificate = coreComponentCertificate.getCertificate();
                    } else {
                        // platform component case
                        Platform platform = platformRepository.findOne(platformId);
                        if (platform != null) {
                            componentCertificate = platform.getComponentCertificates().get(clientId);
                        }
                    }
                    // if the token is to be valid, the certificate must not be null
                    if (componentCertificate == null)
                        return ValidationStatus.INVALID_TRUST_CHAIN;
                    // check if subject certificate is not expired
                    if (isExpired(componentCertificate.getX509())) {
                        return ValidationStatus.EXPIRED_SUBJECT_CERTIFICATE;
                    }
                    // checking if SPK matches the components certificate
                    if (!Base64.getEncoder().encodeToString(componentCertificate.getX509().getPublicKey().getEncoded()).equals(spk))
                        return ValidationStatus.REVOKED_SPK;
                } else { // user case
                    // check if we have such a user and his certificate
                    if (!userRepository.exists(userFromToken)
                            || !userRepository.findOne(userFromToken).getClientCertificates().containsKey(clientId))
                        return ValidationStatus.INVALID_TRUST_CHAIN;
                    // expiry check
                    if (isExpired(userRepository.findOne(userFromToken).getClientCertificates().get(clientId).getX509())) {
                        return ValidationStatus.EXPIRED_SUBJECT_CERTIFICATE;
                    }
                    // and if it matches the client's currently assigned cert
                    if (!userRepository.exists(userFromToken) || !userRepository.findOne(userFromToken).getClientCertificates().containsKey(clientId))
                        return ValidationStatus.REVOKED_SPK;
                    // checking match from token
                    if (!Base64.getEncoder().encodeToString(userRepository.findOne(userFromToken).getClientCertificates().get(clientId).getX509().getPublicKey().getEncoded()).equals(spk))
                        return ValidationStatus.REVOKED_SPK;
                }
            }
            if (!validateFederationAttributes(token)) {
                return ValidationStatus.REVOKED_TOKEN;
            }
            //TODO @JT please review
            ValidationStatus foreignTokenStatus = confirmCertificateValidity(token);
            if (foreignTokenStatus != ValidationStatus.VALID)
                return foreignTokenStatus;
        } catch (ValidationException | IOException | CertificateException | NoSuchAlgorithmException |
                KeyStoreException | NoSuchProviderException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }
        return ValidationStatus.VALID;
    }

    public ValidationStatus validateRemotelyIssuedToken(String tokenString, String clientCertificate, String clientCertificateSigningAAMCertificate, String foreignTokenIssuingAAMCertificate) throws
            CertificateException,
            ValidationException, NoSuchAlgorithmException, NoSuchProviderException,
            KeyStoreException, IOException {
        // if the certificate is not empty, then check the trust chain
        if (!clientCertificate.isEmpty() && !clientCertificateSigningAAMCertificate.isEmpty()) {
            try {
                // foreign token needs additional trust chain validation
                if (new Token(tokenString).getType().equals(Token.Type.FOREIGN)
                        && (foreignTokenIssuingAAMCertificate.isEmpty()
                        || !isForeignTokenIssuerCertificateChainTrusted(foreignTokenIssuingAAMCertificate)))
                    return ValidationStatus.INVALID_TRUST_CHAIN;

                // reject on failed client certificate trust chain
                if (!isClientCertificateChainTrusted(clientCertificateSigningAAMCertificate, clientCertificate))
                    return ValidationStatus.INVALID_TRUST_CHAIN;

                // reject on certificate not matching the token
                if (!doCertificatesMatchTokenFields(
                        tokenString,
                        clientCertificate,
                        clientCertificateSigningAAMCertificate,
                        foreignTokenIssuingAAMCertificate))
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
        PublicKey publicKey = issuerAAM.getAamCACertificate().getX509().getPublicKey();

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
                    aamAddress + SecurityConstants.AAM_VALIDATE_CREDENTIALS,
                    entity, ValidationStatus.class);
            return status.getBody();
        } catch (Exception e) {
            log.error(e);
            // when there is problem with request
            return ValidationStatus.WRONG_AAM;
        }
    }

    private boolean doCertificatesMatchTokenFields(String tokenString,
                                                   String clientCertificateString,
                                                   String clientCertificateSigningAAMCertificate,
                                                   String foreignTokenIssuingAAMCertificate) throws
            IOException, ValidationException, CertificateException {
        Token token = new Token(tokenString);

        X509Certificate clientCertificate = CryptoHelper.convertPEMToX509(clientCertificateString);
        // ref client certificate CN=username@clientId@platformId (or SymbIoTe_Core_AAM for core user)
        String[] clientCommonNameFields = clientCertificate.getSubjectDN().getName().split("CN=")[1].split("@");
        if (clientCommonNameFields.length != 3)
            return false;

        X509Certificate tokenIssuerCertificate;
        switch (token.getType()) {
            case HOME:
                tokenIssuerCertificate = CryptoHelper.convertPEMToX509(clientCertificateSigningAAMCertificate);
                break;
            case FOREIGN:
                tokenIssuerCertificate = CryptoHelper.convertPEMToX509(foreignTokenIssuingAAMCertificate);
                break;
            default: // shouldn't really get here ever
                return false;
        }
        String tokenIssuer = tokenIssuerCertificate.getSubjectDN().getName().split("CN=")[1];
        PublicKey tokenIssuerKey = tokenIssuerCertificate.getPublicKey();

        // ISS check
        if (!token.getClaims().getIssuer().equals(tokenIssuer))
            return false;

        // IPK check
        if (!token.getClaims().get("ipk").equals(Base64.getEncoder().encodeToString(tokenIssuerKey.getEncoded())))
            return false;

        // signature check
        if (JWTEngine.validateTokenString(tokenString, tokenIssuerKey) != ValidationStatus.VALID)
            return false;

        // SPK check
        if (!token.getClaims().get("spk").equals(Base64.getEncoder().encodeToString(clientCertificate.getPublicKey().getEncoded())))
            return false;

        // last SUB & CN check
        switch (token.getType()) {
            case HOME:
                // ref client certificate CN=username@clientId@platformId (or SymbIoTe_Core_AAM for core user)
                if (!token.getClaims().getIssuer().equals(clientCommonNameFields[2]))
                    return false;
                // ref SUB: username@clientIdentifier
                if (!token.getClaims().getSubject().equals(clientCommonNameFields[0] + "@" + clientCommonNameFields[1]))
                    return false;
                break;
            case FOREIGN:
                // ref SUB: username@clientIdentifier@homeAAMInstanceIdentifier
                if (!token.getClaims().getSubject().equals(
                        clientCommonNameFields[0]
                                + "@"
                                + clientCommonNameFields[1]
                                + "@"
                                + CryptoHelper.convertPEMToX509(clientCertificateSigningAAMCertificate).getSubjectDN().getName().split("CN=")[1]))
                    return false;
                break;
            case GUEST:
                return true;
            case NULL:
                // shouldn't really get here ever
                return false;
        }

        // passed matching
        return true;
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

    public boolean isClientCertificateChainTrusted(String signingAAMCertificateString, String clientCertificateString) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        X509Certificate rootCertificate = certificationAuthorityHelper.getRootCACertificate();

        // convert certificates to X509
        X509Certificate clientCertificate = CryptoHelper.convertPEMToX509(clientCertificateString);
        X509Certificate signingAAMCertificate = CryptoHelper.convertPEMToX509(signingAAMCertificateString);

        // Create the selector that specifies the starting certificate
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(clientCertificate);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        TrustAnchor trustAnchor = new TrustAnchor(rootCertificate, null);
        trustAnchors.add(trustAnchor);

        // List of intermediate certificates
        List<X509Certificate> intermediateCertificates = new ArrayList<>();
        intermediateCertificates.add(signingAAMCertificate);
        intermediateCertificates.add(clientCertificate);

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
            // path should have 2 certs in symbIoTe architecture
            return result.getCertPath().getCertificates().size() == 2;
        } catch (CertPathBuilderException | InvalidAlgorithmParameterException e) {
            log.info(e);
            return false;
        }
    }


    public boolean isForeignTokenIssuerCertificateChainTrusted(String foreignTokenIssuerCertificateString) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        X509Certificate rootCertificate = certificationAuthorityHelper.getRootCACertificate();

        // for foreign tokens issued by Core AAM
        if (foreignTokenIssuerCertificateString.equals(CryptoHelper.convertX509ToPEM(rootCertificate)))
            return true;

        // convert certificates to X509
        X509Certificate foreignTokenIssuerCertificate = CryptoHelper.convertPEMToX509(foreignTokenIssuerCertificateString);

        // Create the selector that specifies the starting certificate
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(foreignTokenIssuerCertificate);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        TrustAnchor trustAnchor = new TrustAnchor(rootCertificate, null);
        trustAnchors.add(trustAnchor);

        // List of intermediate certificates
        List<X509Certificate> intermediateCertificates = new ArrayList<>();
        intermediateCertificates.add(foreignTokenIssuerCertificate);

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
            // path should have 1 intermediate cert in symbIoTe architecture
            return result.getCertPath().getCertificates().size() == 1;
        } catch (CertPathBuilderException | InvalidAlgorithmParameterException e) {
            log.info(e);
            return false;
        }
    }

    private boolean validateFederationAttributes(String foreignToken) throws ValidationException {
        JWTClaims claims;
        try {
            claims = JWTEngine.getClaimsFromToken(foreignToken);
        } catch (MalformedJWTException e) {
            return false;
        }

        if (!new Token(foreignToken).getType().equals(Token.Type.FOREIGN))
            return true;

        for (String federationId : claims.getAtt().values()) {
            if (!federationRulesRepository.exists(federationId)
                    || claims.getSub().split(illegalSign).length != 3
                    || !federationRulesRepository.findOne(federationId).getPlatformIds().contains(claims.getSub().split(illegalSign)[2])) {
                return false;
            }
        }
        return true;
    }

    // TODO @JT please review
    public ValidationStatus validateClientCertificate(String foreignToken) throws CertificateException, MalformedJWTException {
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(foreignToken);
        String userFromToken = claimsFromToken.getSub().split("@")[0];
        String clientID = claimsFromToken.getSub().split("@")[1];
        PublicKey userPublicKey = null;
        if (userRepository.exists(userFromToken)) {
            if (userRepository.findOne(userFromToken).getClientCertificates().get(clientID) != null)
                userPublicKey = userRepository.findOne(userFromToken)
                        .getClientCertificates()
                        .get(clientID)
                        .getX509()
                        .getPublicKey();
            // TODO Compare userPublicKey with the one from ForeignToken
                return ValidationStatus.VALID;
        }
        return ValidationStatus.EXPIRED_TOKEN;
    }

    // TODO @JT Please review
    public ValidationStatus confirmCertificateValidity(String token) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        if (!aamServices.getAvailableAAMs().values().isEmpty()) {
            String aamAddress = aamServices.getAvailableAAMs().get(token.split("@")[2]).getAamAddress();
            if (aamAddress != null)
                return restTemplate.postForEntity(aamAddress + SecurityConstants.AAM_VALIDATE_CLIENT_CERTIFICATE,
                        token,
                        ValidationStatus.class).getBody();
        }
        //TODO Handle occuring problem in a better way
        return ValidationStatus.WRONG_AAM;
    }
}
