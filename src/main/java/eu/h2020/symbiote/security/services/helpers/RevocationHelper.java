package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.RevokedTokensRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

/**
 * Helper for revoking credentials.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Piotr Kicki (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class RevocationHelper {

    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;
    private final PlatformRepository platformRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final RevokedTokensRepository revokedTokensRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final Log log = LogFactory.getLog(RevocationHelper.class);
    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;


    @Autowired
    public RevocationHelper(PlatformRepository platformRepository, RevokedKeysRepository revokedKeysRepository,
                            RevokedTokensRepository revokedTokensRepository, UserRepository userRepository,
                            PasswordEncoder passwordEncoder, CertificationAuthorityHelper certificationAuthorityHelper) {
        this.platformRepository = platformRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.revokedTokensRepository = revokedTokensRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
    }

    private boolean revokeCertificateUsingCommonName(User user, String commonName) throws WrongCredentialsException, CertificateException {
        if (commonName.split(illegalSign).length == 1) {
            if (user.getRole() == UserRole.PLATFORM_OWNER) {
                return revokePlatformCertificateUsingCommonName(user, commonName);
            } else {
                throw new SecurityException();
            }
        } else if (commonName.split(illegalSign).length == 2) {
            if (commonName.split(illegalSign)[0].equals(user.getUsername())) {
                return revokeUserCertificateUsingCommonName(user, commonName);
            } else {
                if (user.getRole() == UserRole.PLATFORM_OWNER) {
                    return revokePlatformComponentCertificateUsingCommonName(user, commonName);
                } else {
                    throw new SecurityException();
                }
            }
        } else throw new WrongCredentialsException();
    }

    private boolean revokePlatformComponentCertificateUsingCommonName(User user, String commonName) throws WrongCredentialsException, CertificateException {
        String platformId = commonName.split(illegalSign)[1];
        String componentId = commonName.split(illegalSign)[0];
        Platform platform = user.getOwnedPlatforms().get(platformId);
        if (platform == null || platform.getComponentCertificates().get(componentId) == null ||
                platform.getComponentCertificates().get(componentId).getCertificateString().isEmpty() ||
                !isMyCertificate(platform.getComponentCertificates().get(componentId).getX509())) {
            throw new WrongCredentialsException();
        }
        revokeKey(platformId, platform.getComponentCertificates().get(componentId));
        platform.getComponentCertificates().remove(componentId);
        platformRepository.save(platform);
        return true;
    }

    private boolean revokeUserCertificateUsingCommonName(User user, String commonName) throws WrongCredentialsException, CertificateException {
        String clientId = commonName.split(illegalSign)[1];
        if (user.getClientCertificates().get(clientId) == null) {
            throw new WrongCredentialsException();
        }
        if (user.getClientCertificates().get(clientId).getCertificateString().isEmpty() ||
                !isMyCertificate(user.getClientCertificates().get(clientId).getX509())) {
            throw new CertificateException();
        }
        revokeKey(user.getUsername(), user.getClientCertificates().get(clientId));
        user.getClientCertificates().remove(clientId);
        userRepository.save(user);
        return true;
    }

    private boolean revokePlatformCertificateUsingCommonName(User user, String commonName) throws WrongCredentialsException, CertificateException {
        Platform platform = user.getOwnedPlatforms().get(commonName);
        if (platform == null) {
            throw new WrongCredentialsException();
        }
        if (platform.getPlatformAAMCertificate() == null ||
                platform.getPlatformAAMCertificate().getCertificateString().isEmpty() ||
                !isMyCertificate(platform.getPlatformAAMCertificate().getX509())) {
            throw new CertificateException();
        }
        revokeKey(commonName, platform.getPlatformAAMCertificate());
        platform.setPlatformAAMCertificate(new Certificate());
        platformRepository.save(platform);
        return true;
    }

    private boolean revokeCertificateUsingCertificate(User user, X509Certificate certificate) throws WrongCredentialsException, CertificateException, IOException {
        if (!isMyCertificate(certificate)) {
            throw new CertificateException();
        }
        if (certificate.getSubjectDN().getName().split("CN=").length != 2) {
            throw new CertificateException();
        }
        if (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign).length == 1) {
            if (user.getRole() == UserRole.PLATFORM_OWNER) {
                return revokePlatformCertificateUsingCertificate(user, certificate);
            } else {
                throw new SecurityException();
            }
        } else if (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign).length == 2) {
            if (user.getRole() == UserRole.PLATFORM_OWNER) {
                return revokePlatformComponentCertificateUsingCertificate(user, certificate);
            } else {
                throw new SecurityException();
            }
        } else if (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign).length == 3) {
            if (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0].equals(user.getUsername())) {
                return revokeUserCertificateUsingCertificate(user, certificate);
            } else {
                throw new WrongCredentialsException();
            }
        } else throw new CertificateException();
    }

    private boolean isMyCertificate(X509Certificate certificate) {
        if (certificate.getIssuerDN().getName().split("CN=")[1].equals(certificationAuthorityHelper.getAAMInstanceIdentifier())) {
            return true;
        }
        return false;
    }

    private boolean revokeUserCertificateUsingCertificate(User user, X509Certificate certificate) throws CertificateException, WrongCredentialsException, IOException {
        String clientId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[1];
        if (user.getClientCertificates().get(clientId) == null || user.getClientCertificates().get(clientId).getCertificateString().isEmpty()) {
            throw new CertificateException();
        }
        if (user.getClientCertificates().get(clientId).getCertificateString().equals(CryptoHelper.convertX509ToPEM(certificate))) {
            revokeKey(user.getUsername(), user.getClientCertificates().get(clientId));
            user.getClientCertificates().remove(clientId);
            userRepository.save(user);
            return true;
        } else if (isRevoked(user.getUsername(), certificate.getPublicKey())) {
            return true;
        } else throw new WrongCredentialsException();
    }

    private boolean revokePlatformComponentCertificateUsingCertificate(User user, X509Certificate certificate) throws CertificateException, WrongCredentialsException, IOException {
        String componentId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
        String platformId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[1];
        Platform platform = user.getOwnedPlatforms().get(platformId);
        if (platform != null && platform.getComponentCertificates().get(componentId) != null) {

            if (platform.getComponentCertificates().get(componentId).getCertificateString().isEmpty()) {
                throw new CertificateException();
            }
            if (platform.getComponentCertificates().get(componentId).getCertificateString().equals(CryptoHelper.convertX509ToPEM(certificate))) {
                revokeKey(platformId, platform.getComponentCertificates().get(componentId));
                platform.getComponentCertificates().remove(componentId);
                platformRepository.save(platform);
                return true;
            } else if (isRevoked(platformId, certificate.getPublicKey())) {
                return true;
            } else throw new WrongCredentialsException();


        } else {
            throw new WrongCredentialsException();
        }
    }

    private boolean revokePlatformCertificateUsingCertificate(User user, X509Certificate certificate) throws CertificateException, WrongCredentialsException, IOException {
        String platformId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
        Platform platform = user.getOwnedPlatforms().get(platformId);
        if (platform != null) {
            if (platform.getPlatformAAMCertificate() == null || platform.getPlatformAAMCertificate().getCertificateString().isEmpty()) {
                throw new CertificateException();
            }
            if (platform.getPlatformAAMCertificate().getCertificateString().equals(CryptoHelper.convertX509ToPEM(certificate))) {
                revokeKey(platformId, platform.getPlatformAAMCertificate());
                platform.setPlatformAAMCertificate(new Certificate());
                platformRepository.save(platform);
                return true;
            } else if (isRevoked(platformId, certificate.getPublicKey())) {
                return true;
            } else throw new WrongCredentialsException();
        } else {
            throw new WrongCredentialsException();
        }
    }

    // certificate revoke function - not finished
    public boolean revokeCertificate(Credentials credentials, Certificate certificate, String commonName)
            throws CertificateException, WrongCredentialsException, NotExistingUserException, IOException {
        if (credentials.getUsername().isEmpty()) {
            throw new WrongCredentialsException();
        }
        User user = userRepository.findOne(credentials.getUsername());
        if (user == null || user.getRole() == UserRole.NULL) {
            throw new NotExistingUserException();
        }
        if (passwordEncoder.matches(credentials.getPassword(), user.getPasswordEncrypted())) {
            if (!commonName.isEmpty()) {
                return revokeCertificateUsingCommonName(user, commonName);
            } else if (!certificate.getCertificateString().isEmpty()) {
                X509Certificate x509Certificate;
                try {
                    x509Certificate = certificate.getX509();
                } catch (Exception e) {
                    throw new CertificateException();
                }

                return revokeCertificateUsingCertificate(user, x509Certificate);
            } else {
                throw new WrongCredentialsException();
            }

        } else {
            throw new WrongCredentialsException();
        }
    }

    // token revokeHomeToken function
    public boolean revokeHomeToken(Credentials credentials, Token token) throws CertificateException, WrongCredentialsException,
            NotExistingUserException, ValidationException {
        if (JWTEngine.validateTokenString(token.getToken()) != ValidationStatus.VALID) {
            throw new ValidationException("Invalid token");
        }
        // user token revocation
        User user = userRepository.findOne(credentials.getUsername());
        if (user != null) {
            if (passwordEncoder.matches(credentials.getPassword(), user.getPasswordEncrypted())) {
                // user
                if (token.getClaims().get("sub").toString().split(illegalSign).length == 2 &&
                        user.getClientCertificates().get(token.getClaims().get("sub").toString().split(illegalSign)[1]) != null &&
                        Base64.getEncoder().encodeToString(user.getClientCertificates().get(token.getClaims().get("sub").toString().split(illegalSign)[1]).getX509().getPublicKey().getEncoded())
                        .equals(token.getClaims().get("spk"))) {
                    revokedTokensRepository.save(token);
                    return true;
                }
                // platform owner
                Platform platform = platformRepository.findByPlatformOwner(user);
                if (platform != null &&
                        !platform.getPlatformAAMCertificate().getCertificateString().isEmpty() &&
                        Base64.getEncoder().encodeToString(platform.getPlatformAAMCertificate().getX509().getPublicKey().getEncoded())
                        .equals(token.getClaims().get("ipk").toString())) {
                    revokedTokensRepository.save(token);
                    return true;
                }
                throw new ValidationException("You have no rights to this token");
            } else {
                throw new WrongCredentialsException();
            }
        } else {
            throw new NotExistingUserException();
        }
    }

    private boolean isForeignTokenValid(Token foreignToken, Token remoteHomeToken) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException, MalformedJWTException {
        JWTClaims remoteHomeTokenClaims = JWTEngine.getClaimsFromToken(remoteHomeToken.toString());
        JWTClaims foreignTokenClaims = JWTEngine.getClaimsFromToken(foreignToken.toString());
        if (!certificationAuthorityHelper.getAAMInstanceIdentifier().equals(foreignTokenClaims.getIss())) {
            return false;
        }
        if (!foreignTokenClaims.getIpk().equals(Base64.getEncoder().encodeToString(certificationAuthorityHelper.getAAMPublicKey().getEncoded()))) {
            return false;
        }
        if (remoteHomeToken.getClaims().getSubject().split(illegalSign).length != 2 || foreignToken.getClaims().getSubject().split(illegalSign).length != 3) {
            return false;
        }
        if (!foreignTokenClaims.getSub().split(illegalSign)[0].equals(remoteHomeTokenClaims.getSub().split(illegalSign)[0]) ||
                !foreignTokenClaims.getSub().split(illegalSign)[1].equals(remoteHomeTokenClaims.getSub().split(illegalSign)[1]) ||
                !foreignTokenClaims.getSub().split(illegalSign)[2].equals(remoteHomeTokenClaims.getIss())) {
            return false;
        }
        if (!foreignToken.getClaims().get("spk").equals(remoteHomeToken.getClaims().get("spk"))) {
            return false;
        }
        return true;

    }

    public boolean revokeForeignToken(Token remoteHomeToken, Token foreignToken) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, MalformedJWTException {

        if (isForeignTokenValid(foreignToken, remoteHomeToken)) {
            revokedTokensRepository.save(foreignToken);
            return true;
        }
        throw new IllegalArgumentException();
    }

    private void revokeKey(String name, Certificate cert) throws CertificateException {
        SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(name);
        Set<String> keySet = (subjectsRevokedKeys == null) ? new HashSet<>() : subjectsRevokedKeys
                .getRevokedKeysSet();
        keySet.add(Base64.getEncoder().encodeToString(
                cert.getX509().getPublicKey().getEncoded()));
        // adding key to revoked repository
        revokedKeysRepository.save(new SubjectsRevokedKeys(name, keySet));
    }

    private boolean isRevoked(String name, PublicKey publicKey) {
        SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(name);
        if (subjectsRevokedKeys == null) {
            return false;
        }
        Set<String> keySet = subjectsRevokedKeys.getRevokedKeysSet();
        return keySet.contains(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
    }


    public boolean revokeCertificateAdmin(Credentials credentials, Certificate certificate, String certificateCommonName) {


        throw new IllegalArgumentException();
    }

    public boolean revokeHomeTokenByAdmin(Credentials credentials, Token token) throws WrongCredentialsException, ValidationException {
        if (passwordEncoder.matches(credentials.getPassword(), AAMOwnerPassword)) {
            if (JWTEngine.validateTokenString(token.getToken()) != ValidationStatus.VALID) {
                throw new ValidationException("Invalid token");
            }
            revokedTokensRepository.save(token);
        }
        throw new WrongCredentialsException();
    }

    //TODO use it if AAM key was revoked
    /*
    private boolean isCertificateChainTrustedOrRevoked(String certificateString) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {
        if (!isCertificateChainTrusted(certificateString)){
            if (revokedKeysRepository.findOne(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID)!=null){
                X509Certificate certificate = CryptoHelper.convertPEMToX509(certificateString);
                //TODO cert
                return revokedKeysRepository.findOne(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID).getRevokedKeysSet().contains(null) ;
            }
        }
        return true;
    }

    private boolean isCertificateChainTrusted(String certificateString) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        X509Certificate rootCertificate = certificationAuthorityHelper.getAAMCertificate();

        // for foreign tokens issued by Core AAM
        if (certificateString.equals(CryptoHelper.convertX509ToPEM(rootCertificate)))
            return true;

        // convert certificates to X509
        X509Certificate certificate = CryptoHelper.convertPEMToX509(certificateString);

        // Create the selector that specifies the starting certificate
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(certificate);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        TrustAnchor trustAnchor = new TrustAnchor(rootCertificate, null);
        trustAnchors.add(trustAnchor);

        // List of intermediate certificates
        List<X509Certificate> intermediateCertificates = new ArrayList<>();
        intermediateCertificates.add(certificate);


     // If build() returns successfully, the certificate is valid. More details
     // about the valid path can be obtained through the PKIXCertPathBuilderResult.
     // If no valid path can be found, a CertPathBuilderException is thrown.

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
    */
}
