package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.model.mim.FederationMember;
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
import eu.h2020.symbiote.security.repositories.entities.RevokedRemoteToken;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.CacheService;
import io.jsonwebtoken.Claims;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
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
import java.util.Map;
import java.util.stream.Collectors;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.FIELDS_DELIMITER;

/**
 * Used to validate given credentials against data in the AAMs
 * <p>
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Piotr Kicki (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class ValidationHelper {

    private static Log log = LogFactory.getLog(ValidationHelper.class);

    // AAM configuration
    private final String deploymentId;
    private final IssuingAuthorityType deploymentType;
    public final CertificationAuthorityHelper certificationAuthorityHelper;
    private final RevokedKeysRepository revokedKeysRepository;
    private final RevokedTokensRepository revokedTokensRepository;
    private final RevokedRemoteTokensRepository revokedRemoteTokensRepository;
    private final FederationsRepository federationsRepository;
    private final UserRepository userRepository;
    private final ComponentCertificatesRepository componentCertificatesRepository;
    private final AAMServices aamServices;
    private final CacheService cacheService;

    // usable
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;
    @Value("${aam.deployment.validation.allow-offline}")
    private boolean isOfflineEnough;

    @Autowired
    public ValidationHelper(CertificationAuthorityHelper certificationAuthorityHelper,
                            RevokedKeysRepository revokedKeysRepository,
                            RevokedTokensRepository revokedTokensRepository,
                            RevokedRemoteTokensRepository revokedRemoteTokensRepository,
                            FederationsRepository federationsRepository,
                            UserRepository userRepository,
                            ComponentCertificatesRepository componentCertificatesRepository,
                            AAMServices aamServices,
                            CacheService cacheService) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.revokedKeysRepository = revokedKeysRepository;
        this.revokedTokensRepository = revokedTokensRepository;
        this.revokedRemoteTokensRepository = revokedRemoteTokensRepository;
        this.federationsRepository = federationsRepository;
        this.userRepository = userRepository;
        this.componentCertificatesRepository = componentCertificatesRepository;
        this.aamServices = aamServices;
        this.cacheService = cacheService;
    }

    public ValidationStatus validate(String token,
                                     String clientCertificate,
                                     String clientCertificateSigningAAMCertificate,
                                     String foreignTokenIssuingAAMCertificate) {
        try {
            // basic validation (signature and exp)
            ValidationStatus validationStatus = JWTEngine.validateTokenString(token);
            if (validationStatus != ValidationStatus.VALID) {
                return validationStatus;
            }

            Token tokenForValidation = new Token(token);
            if (cacheService.isValidTokenCached(tokenForValidation)) {
                return ValidationStatus.VALID;
            }

            Claims claims = tokenForValidation.getClaims();
            String spk = claims.get("spk").toString();
            String ipk = claims.get("ipk").toString();

            // check if token issued by us
            if (!deploymentId.equals(claims.getIssuer())) {
                // not our token, but the Core AAM knows things ;)
                if (deploymentType == IssuingAuthorityType.CORE
                        && revokedKeysRepository.exists(claims.getIssuer()) // check if IPK is in the revoked set
                        && revokedKeysRepository.findOne(claims.getIssuer()).getRevokedKeysSet().contains(ipk))
                    return ValidationStatus.REVOKED_IPK;

                // relay validation to issuer
                return validateRemotelyIssuedToken(token, clientCertificate, clientCertificateSigningAAMCertificate, foreignTokenIssuingAAMCertificate);
            }
            // It is a token issued by us, so full checkup ahead.

            // check if issuer certificate is not expired
            if (isExpired(certificationAuthorityHelper.getAAMCertificate()))
                return ValidationStatus.EXPIRED_ISSUER_CERTIFICATE;
            // TODO possibly throw runtime exception so that AAM crashes as it is no more valid

            // check IPK is not equal to current AAM PK
            if (!Base64.getEncoder().encodeToString(
                    certificationAuthorityHelper.getAAMCertificate().getPublicKey().getEncoded()).equals(ipk)) {
                return ValidationStatus.INVALID_TRUST_CHAIN;
            }

            // check revoked JTI
            if (revokedTokensRepository.exists(claims.getId())) {
                return ValidationStatus.REVOKED_TOKEN;
            }

            String userFromToken = claims.getSubject().split(FIELDS_DELIMITER)[0];

            // check if SPK is is in the revoked repository
            if (revokedKeysRepository.exists(userFromToken) && revokedKeysRepository.findOne(userFromToken).getRevokedKeysSet().contains(spk)) {
                return ValidationStatus.REVOKED_SPK;
            }

            switch (tokenForValidation.getType()) {
                case HOME:
                    // check if subject certificate is valid & matching the token SPK
                    switch (claims.getSubject().split(FIELDS_DELIMITER).length) {
                        case 1: // local components case
                            Certificate certificate = null;
                            // component case - SUB/userFromToken is component name, ISS is AAM instanceId
                            ComponentCertificate localComponentCertificate = componentCertificatesRepository.findOne(userFromToken);
                            if (localComponentCertificate != null)
                                certificate = localComponentCertificate.getCertificate();
                            // if the token is to be valid, the certificate must not be null
                            if (certificate == null)
                                return ValidationStatus.INVALID_TRUST_CHAIN;
                            // check if subject certificate is not expired
                            if (isExpired(certificate.getX509())) {
                                return ValidationStatus.EXPIRED_SUBJECT_CERTIFICATE;
                            }
                            // checking if SPK matches the components certificate
                            if (!Base64.getEncoder().encodeToString(certificate.getX509().getPublicKey().getEncoded()).equals(spk))
                                return ValidationStatus.REVOKED_SPK;
                            break;
                        case 2: // user token case
                            String clientId = claims.getSubject().split(FIELDS_DELIMITER)[1];
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
                            break;
                    }
                    break;
                case FOREIGN:
                    // checking if the token is still valid against current federation definitions
                    if (!validateFederationAttributes(token)) {
                        revokedTokensRepository.save(tokenForValidation);
                        return ValidationStatus.REVOKED_TOKEN;
                    }

                    // check if the foreign token origin credentials are still valid
                    ValidationStatus originCredentialsValidationStatus = reachOutForeignTokenOriginCredentialsAAMToValidateThem(token);
                    switch (originCredentialsValidationStatus) {
                        case VALID:
                            // origin credentials are valid
                            cacheService.cacheValidToken(tokenForValidation);
                            break;
                        case UNKNOWN:
                        case WRONG_AAM:
                            // there was some issue with validating the origin credentials
                            return originCredentialsValidationStatus;
                        default:
                            // we confirmed the origin credentials were invalidated and we need to invalidate our token
                            revokedTokensRepository.save(tokenForValidation);
                            return originCredentialsValidationStatus;
                    }
                    break;
                case GUEST:
                    break;
                case NULL:
                    break;
                default:
                    break;
            }
        } catch (ValidationException | IOException | CertificateException | NoSuchAlgorithmException |
                KeyStoreException | NoSuchProviderException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }
        return ValidationStatus.VALID;
    }

    public ValidationStatus validateRemotelyIssuedToken(String tokenString,
                                                        String clientCertificate,
                                                        String clientCertificateSigningAAMCertificate,
                                                        String foreignTokenIssuingAAMCertificate) throws
            CertificateException,
            ValidationException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        // check if already cached
        if (cacheService.isValidTokenCached(new Token(tokenString))) {
            return ValidationStatus.VALID;
        }

        Claims claims = JWTEngine.getClaims(tokenString);
        //checking if token is revoked
        if (revokedRemoteTokensRepository.exists(claims.getIssuer() + FIELDS_DELIMITER + claims.getId())) {
            return ValidationStatus.REVOKED_TOKEN;
        }

        // if the certificate is not empty, then check the trust chain
        if (!clientCertificate.isEmpty() && !clientCertificateSigningAAMCertificate.isEmpty()) {
            try {
                // foreign token needs additional trust chain validation
                if (new Token(tokenString).getType().equals(Token.Type.FOREIGN)
                        && (foreignTokenIssuingAAMCertificate.isEmpty()
                        || !certificationAuthorityHelper.isServiceCertificateChainTrusted(foreignTokenIssuingAAMCertificate)))
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
            } catch (NullPointerException npe) {
                log.error("Problem with parsing the given PEMs string");
                return ValidationStatus.INVALID_TRUST_CHAIN;
            }
        }
        // TODO attempt connection and fallback to offline if enough

        // end procedure if offline validation is enough, certificates are ok
        if (isOfflineEnough)
            return ValidationStatus.VALID;

        // resolving available AAMs in search of the token issuer
        Map<String, AAM> availableAAMs = aamServices.getAvailableAAMs();

        // validate CoreAAM trust
        if (!certificationAuthorityHelper.getRootCACert()
                .equals(availableAAMs.get(SecurityConstants.CORE_AAM_INSTANCE_ID).getAamCACertificate().getCertificateString()))
            throw new ValidationException(ValidationException.CERTIFICATE_MISMATCH);

        String issuer = claims.getIssuer();
        // Core does not know such an issuer and therefore this might be a forfeit
        if (!availableAAMs.containsKey(issuer))
            return ValidationStatus.INVALID_TRUST_CHAIN;
        AAM issuerAAM = availableAAMs.get(issuer);
        String aamAddress = issuerAAM.getAamAddress();

        if (issuerAAM.getAamCACertificate().getCertificateString().isEmpty()) {
            throw new CertificateException();
        }
        if (!certificationAuthorityHelper.isServiceCertificateChainTrusted(issuerAAM.getAamCACertificate().getCertificateString())) {
            return ValidationStatus.INVALID_TRUST_CHAIN;
        }

        // check IPK
        PublicKey publicKey = issuerAAM.getAamCACertificate().getX509().getPublicKey();
        if (!Base64.getEncoder().encodeToString(publicKey.getEncoded()).equals(claims.get("ipk"))) {
            return ValidationStatus.INVALID_TRUST_CHAIN;
        }
        // TODO use the AAMClient
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
            switch (status.getBody()) {
                case VALID:
                    cacheService.cacheValidToken(new Token(tokenString));
                    return status.getBody();
                case UNKNOWN:
                case WRONG_AAM:
                    // there was some issue with validating the origin credentials
                    return status.getBody();
                default:
                    // we need to invalidate our token
                    revokedRemoteTokensRepository.save(new RevokedRemoteToken(claims.getIssuer() + FIELDS_DELIMITER + claims.getId()));
                    return status.getBody();
            }
        } catch (Exception e) {
            log.error(e);
            // when there is problem with request
            // end procedure if offline validation is enough, certificates are ok, no connection with certificate Issuers
            if (isOfflineEnough)
                return ValidationStatus.VALID;
            return ValidationStatus.WRONG_AAM;
        }
    }

    private boolean doCertificatesMatchTokenFields(String tokenString,
                                                   String clientCertificateString,
                                                   String clientCertificateSigningAAMCertificate,
                                                   String foreignTokenIssuingAAMCertificate) throws
            IOException,
            ValidationException,
            CertificateException {
        Token token = new Token(tokenString);

        X509Certificate clientCertificate = CryptoHelper.convertPEMToX509(clientCertificateString);
        // ref client certificate CN=username@clientId@platformId (or SymbIoTe_Core_AAM for core user)
        String[] clientCommonNameFields = clientCertificate.getSubjectDN().getName().split("CN=")[1].split(FIELDS_DELIMITER);
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
                if (!token.getClaims().getSubject().equals(clientCommonNameFields[0] + FIELDS_DELIMITER + clientCommonNameFields[1]))
                    return false;
                break;
            case FOREIGN:
                // ref SUB: username@clientIdentifier@homeAAMInstanceIdentifier
                if (!token.getClaims().getSubject().equals(
                        clientCommonNameFields[0]
                                + FIELDS_DELIMITER
                                + clientCommonNameFields[1]
                                + FIELDS_DELIMITER
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

    public boolean isClientCertificateChainTrusted(String signingAAMCertificateString,
                                                   String clientCertificateString) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        String rootCertificate = CryptoHelper.convertX509ToPEM(certificationAuthorityHelper.getRootCACertificate());
        return CryptoHelper.isClientCertificateChainTrusted(rootCertificate, signingAAMCertificateString, clientCertificateString);
    }


    private boolean validateFederationAttributes(String foreignToken) {
        JWTClaims claims;
        try {
            claims = JWTEngine.getClaimsFromToken(foreignToken);
        } catch (MalformedJWTException e) {
            return false;
        }
        for (String federationId : claims.getAtt().values()) {
            if (!federationsRepository.exists(federationId)
                    || claims.getSub().split(FIELDS_DELIMITER).length != 4
                    || !federationsRepository.findOne(federationId)
                    .getMembers().stream()
                    .map(FederationMember::getPlatformId)
                    .collect(Collectors.toSet())
                    .contains(claims.getSub().split(FIELDS_DELIMITER)[2]))
                return false;
        }
        return true;
    }

    /**
     * @param foreignToken issued in another AAM that needs confirmation that the HOME token used to issue it is still valid
     */
    public ValidationStatus validateForeignTokenOriginCredentials(String foreignToken) throws
            CertificateException,
            MalformedJWTException {
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(foreignToken);
        // TODO R4 consider component tokens in P2P L2 communication!
        if (claimsFromToken.getSub().split(FIELDS_DELIMITER).length != 4) {
            throw new MalformedJWTException(MalformedJWTException.TOKEN_SUBJECT_HAS_WRONG_STRUCTURE);
        }

        String userFromToken = claimsFromToken.getSub().split(FIELDS_DELIMITER)[0];
        String clientID = claimsFromToken.getSub().split(FIELDS_DELIMITER)[1];
        String platformId = claimsFromToken.getSub().split(FIELDS_DELIMITER)[2];
        String jti = claimsFromToken.getSub().split(FIELDS_DELIMITER)[3];

        // checking if we issued the Home token
        if (!deploymentId.equals(platformId))
            return ValidationStatus.WRONG_AAM;
        // SUB claim check (searching for user and client)
        if (!userRepository.exists(userFromToken)
                || userRepository.findOne(userFromToken).getClientCertificates().get(clientID) == null) {
            return ValidationStatus.REVOKED_TOKEN;
        }
        if (revokedTokensRepository.exists(jti)) {
            return ValidationStatus.REVOKED_TOKEN;
        }

        // SPK claim check
        PublicKey userPublicKey = userRepository.findOne(userFromToken)
                .getClientCertificates()
                .get(clientID)
                .getX509()
                .getPublicKey();
        if (!claimsFromToken.getSpk().equals(Base64.getEncoder().encodeToString(userPublicKey.getEncoded()))) {
            return ValidationStatus.INVALID_TRUST_CHAIN;
        }
        return ValidationStatus.VALID;
    }

    private ValidationStatus reachOutForeignTokenOriginCredentialsAAMToValidateThem(String stringToken) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            ValidationException {
        Token token = new Token(stringToken);
        String platformId = token.getClaims().getSubject().split(FIELDS_DELIMITER)[2];
        // fetching origin token AAM
        if (aamServices.getAvailableAAMs().get(platformId) == null) {
            return ValidationStatus.INVALID_TRUST_CHAIN;
        }
        String aamAddress = aamServices.getAvailableAAMs().get(platformId).getAamAddress();
        try {
            // issuing origin credentials check in the origin token HOME AAM
            return restTemplate.postForEntity(aamAddress + SecurityConstants.AAM_VALIDATE_FOREIGN_TOKEN_ORIGIN_CREDENTIALS,
                    token.getToken(),
                    ValidationStatus.class).getBody();
        } catch (HttpClientErrorException e) {
            log.error("HomeToken issuer not available");
            return ValidationStatus.UNKNOWN;
        }
    }
}
