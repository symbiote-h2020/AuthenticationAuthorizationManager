package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.*;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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

    private final ComponentCertificatesRepository componentCertificatesRepository;
    private final PlatformRepository platformRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final RevokedTokensRepository revokedTokensRepository;
    private final UserRepository userRepository;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;


    @Autowired
    public RevocationHelper(ComponentCertificatesRepository componentCertificatesRepository, PlatformRepository platformRepository, RevokedKeysRepository revokedKeysRepository,
                            RevokedTokensRepository revokedTokensRepository, UserRepository userRepository,
                            CertificationAuthorityHelper certificationAuthorityHelper) {
        this.componentCertificatesRepository = componentCertificatesRepository;
        this.platformRepository = platformRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.revokedTokensRepository = revokedTokensRepository;
        this.userRepository = userRepository;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
    }

    private boolean revokeCertificateUsingCommonName(User user, String commonName) throws WrongCredentialsException, CertificateException {
        if (commonName.split(illegalSign).length == 1) {
            if (user.getRole() == UserRole.PLATFORM_OWNER) {
                Platform platform = user.getOwnedPlatforms().get(commonName);
                return revokePlatformCertificateUsingCommonName(commonName, platform);
            }
            throw new SecurityException();
        }
        if (commonName.split(illegalSign).length == 2) {
            if (commonName.split(illegalSign)[0].equals(user.getUsername())) {
                String clientId = commonName.split(illegalSign)[1];
                return revokeUserCertificateUsingCommonName(user, clientId);
            }
            if (user.getRole() == UserRole.PLATFORM_OWNER) {
                String componentId = commonName.split(illegalSign)[0];
                String platformId = commonName.split(illegalSign)[1];
                Platform platform = user.getOwnedPlatforms().get(platformId);
                return revokePlatformComponentCertificateUsingCommonName(componentId, platform);
            }
            throw new SecurityException();
        }
        throw new WrongCredentialsException();
    }

    private boolean revokePlatformComponentCertificateUsingCommonName(String componentId, Platform platform) throws WrongCredentialsException, CertificateException {
        if (platform == null
                || platform.getComponentCertificates().get(componentId) == null
                || platform.getComponentCertificates().get(componentId).getCertificateString().isEmpty()
                || !isMyCertificate(platform.getComponentCertificates().get(componentId).getX509())) {
            throw new WrongCredentialsException();
        }
        revokeKey(componentId, platform.getComponentCertificates().get(componentId));
        platform.getComponentCertificates().remove(componentId);
        platformRepository.save(platform);
        return true;
    }

    private boolean revokeUserCertificateUsingCommonName(User user, String clientId) throws WrongCredentialsException, CertificateException {
        if (user.getClientCertificates().get(clientId) == null) {
            throw new WrongCredentialsException();
        }
        if (user.getClientCertificates().get(clientId).getCertificateString().isEmpty()
                || !isMyCertificate(user.getClientCertificates().get(clientId).getX509())) {
            throw new CertificateException();
        }
        revokeKey(user.getUsername(), user.getClientCertificates().get(clientId));
        user.getClientCertificates().remove(clientId);
        userRepository.save(user);
        return true;
    }

    private boolean revokePlatformCertificateUsingCommonName(String commonName, Platform platform) throws WrongCredentialsException, CertificateException {
        if (platform == null) {
            throw new WrongCredentialsException();
        }
        if (platform.getPlatformAAMCertificate() == null
                || platform.getPlatformAAMCertificate().getCertificateString().isEmpty()
                || !isMyCertificate(platform.getPlatformAAMCertificate().getX509())) {
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
                String platformId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
                Platform platform = user.getOwnedPlatforms().get(platformId);
                return revokePlatformCertificateUsingCertificate(certificate, platform);
            }
            throw new SecurityException();
        }
        if (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign).length == 2) {
            if (user.getRole() == UserRole.PLATFORM_OWNER) {
                String platformId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[1];
                Platform platform = user.getOwnedPlatforms().get(platformId);
                return revokePlatformComponentCertificateUsingCertificate(certificate, platform);
            }
            throw new SecurityException();
        }
        if (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign).length == 3) {
            if (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0].equals(user.getUsername())) {
                return revokeUserCertificateUsingCertificate(user, certificate);
            }
            throw new WrongCredentialsException();
        }
        throw new CertificateException();
    }

    private boolean isMyCertificate(X509Certificate certificate) {
        return certificate.getIssuerDN().getName().split("CN=")[1].contains(certificationAuthorityHelper.getAAMInstanceIdentifier());
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
        }
        if (isRevoked(user.getUsername(), certificate.getPublicKey())) {
            return true;
        }
        throw new WrongCredentialsException();
    }


    private boolean revokePlatformComponentCertificateUsingCertificate(X509Certificate certificate, Platform platform) throws CertificateException, WrongCredentialsException, IOException {
        String componentId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
        if (platform == null
                || platform.getComponentCertificates().get(componentId) == null) {
            throw new WrongCredentialsException();
        }
        if (platform.getComponentCertificates().get(componentId).getCertificateString().isEmpty()) {
            throw new CertificateException();
        }
        if (platform.getComponentCertificates().get(componentId).getCertificateString().equals(CryptoHelper.convertX509ToPEM(certificate))) {
            revokeKey(componentId, platform.getComponentCertificates().get(componentId));
            platform.getComponentCertificates().remove(componentId);
            platformRepository.save(platform);
            return true;
        }
        if (isRevoked(componentId, certificate.getPublicKey())) {
            return true;
        }
        throw new WrongCredentialsException();


    }

    private boolean revokePlatformCertificateUsingCertificate(X509Certificate certificate, Platform platform) throws CertificateException, WrongCredentialsException, IOException {
        String platformId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
        if (platform == null) {
            throw new WrongCredentialsException();
        }
        if (platform.getPlatformAAMCertificate() == null
                || platform.getPlatformAAMCertificate().getCertificateString().isEmpty()) {
            throw new CertificateException();
        }
        if (platform.getPlatformAAMCertificate().getCertificateString().equals(CryptoHelper.convertX509ToPEM(certificate))) {
            revokeKey(platformId, platform.getPlatformAAMCertificate());
            platform.setPlatformAAMCertificate(new Certificate());
            platformRepository.save(platform);
            return true;
        }
        if (isRevoked(platformId, certificate.getPublicKey())) {
            return true;
        }
        throw new WrongCredentialsException();
    }

    public boolean revokeCertificate(User user, Certificate certificate, String commonName)
            throws CertificateException, WrongCredentialsException, IOException {

        if (!commonName.isEmpty()) {
            return revokeCertificateUsingCommonName(user, commonName);
        }
        if (!certificate.getCertificateString().isEmpty()) {
            X509Certificate x509Certificate;
            try {
                x509Certificate = certificate.getX509();
            } catch (Exception e) {
                throw new CertificateException();
            }

            return revokeCertificateUsingCertificate(user, x509Certificate);
        }
        throw new CertificateException("Empty CN and cert");


    }

    // token revokeHomeToken function
    public boolean revokeHomeToken(User user, Token token) throws CertificateException, ValidationException {
        if (JWTEngine.validateTokenString(token.getToken()) != ValidationStatus.VALID) {
            throw new ValidationException("Invalid token");
        }
        if (token.getClaims().get("sub").toString().split(illegalSign).length == 2
                && user.getClientCertificates().get(token.getClaims().get("sub").toString().split(illegalSign)[1]) != null
                && Base64.getEncoder().encodeToString(user.getClientCertificates().get(token.getClaims().get("sub").toString().split(illegalSign)[1]).getX509().getPublicKey().getEncoded())
                        .equals(token.getClaims().get("spk"))) {
            revokedTokensRepository.save(token);
            return true;
        }
        // platform owner
        Platform platform = platformRepository.findByPlatformOwner(user);
        if (platform != null
                && !platform.getPlatformAAMCertificate().getCertificateString().isEmpty()
                && Base64.getEncoder().encodeToString(platform.getPlatformAAMCertificate().getX509().getPublicKey().getEncoded())
                        .equals(token.getClaims().get("ipk").toString())) {
            revokedTokensRepository.save(token);
            return true;
        }
        throw new ValidationException("You have no rights to this token");


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
        if (remoteHomeToken.getClaims().getSubject().split(illegalSign).length != 2
                || foreignToken.getClaims().getSubject().split(illegalSign).length != 3) {
            return false;
        }
        if (!foreignTokenClaims.getSub().split(illegalSign)[0].equals(remoteHomeTokenClaims.getSub().split(illegalSign)[0])
                || !foreignTokenClaims.getSub().split(illegalSign)[1].equals(remoteHomeTokenClaims.getSub().split(illegalSign)[1])
                || !foreignTokenClaims.getSub().split(illegalSign)[2].equals(remoteHomeTokenClaims.getIss())) {
            return false;
        }
        return foreignToken.getClaims().get("spk").equals(remoteHomeToken.getClaims().get("spk"));
    }

    public boolean revokeForeignToken(Token remoteHomeToken, Token foreignToken) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, MalformedJWTException {

        if (isForeignTokenValid(foreignToken, remoteHomeToken)) {
            revokedTokensRepository.save(foreignToken);
            return true;
        }
        throw new IllegalArgumentException();
    }

    public boolean revokeCertificateByAdmin(Certificate certificate, String certificateCommonName) throws WrongCredentialsException, CertificateException, IOException, NotExistingUserException {
        if (!certificateCommonName.isEmpty()) {
            if (certificateCommonName.split(illegalSign).length == 1) {
                Platform platform = platformRepository.findOne(certificateCommonName);
                return revokePlatformCertificateUsingCommonName(certificateCommonName, platform);
            }
            if (certificateCommonName.split(illegalSign).length == 2) {
                if (userRepository.findOne(certificateCommonName.split(illegalSign)[0]) != null) {
                    String username = certificateCommonName.split(illegalSign)[0];
                    String clientId = certificateCommonName.split(illegalSign)[1];
                    User user = userRepository.findOne(username);
                    if (user == null
                            || user.getClientCertificates().get(clientId) == null) {
                        throw new WrongCredentialsException();
                    }
                    return revokeUserCertificateUsingCommonName(user, clientId);
                }

                String componentId = certificateCommonName.split(illegalSign)[0];
                String platformId = certificateCommonName.split(illegalSign)[1];
                if (platformId.equals(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID)) {
                    return revokeAAMComponentUsingCommonName(componentId);
                }
                Platform platform = platformRepository.findOne(platformId);
                return revokePlatformComponentCertificateUsingCommonName(componentId, platform);
            }
            throw new WrongCredentialsException();
        }
        if (certificate != null) {
            X509Certificate x509Certificate;
            try {
                x509Certificate = certificate.getX509();
            } catch (Exception e) {
                throw new CertificateException();
            }

            return revokeCertificateUsingCertificateByAdmin(x509Certificate);
        }
        throw new IllegalArgumentException();
    }

    private boolean revokeAAMComponentUsingCommonName(String componentId) throws CertificateException, WrongCredentialsException {
        ComponentCertificate componentCertificate = componentCertificatesRepository.findOne(componentId);
        if (componentCertificate == null
                || componentCertificate.getCertificate() == null
                || componentCertificate.getCertificate().getCertificateString().isEmpty()
                || !isMyCertificate(componentCertificate.getCertificate().getX509())) {
            throw new WrongCredentialsException();
        }
        revokeKey(componentId, componentCertificate.getCertificate());
        componentCertificatesRepository.delete(componentId);
        return true;
    }

    private boolean revokeCertificateUsingCertificateByAdmin(X509Certificate certificate) throws CertificateException, IOException, WrongCredentialsException, NotExistingUserException {
        if (!isMyCertificate(certificate)) {
            throw new CertificateException();
        }
        if (certificate.getSubjectDN().getName().split("CN=").length != 2) {
            throw new CertificateException();
        }
        String certificateCommonName = certificate.getSubjectDN().getName().split("CN=")[1];
        if (certificateCommonName.split(illegalSign).length == 1) {
            Platform platform = platformRepository.findOne(certificateCommonName);
            return revokePlatformCertificateUsingCertificate(certificate, platform);
        }
        if (certificateCommonName.split(illegalSign).length == 2) {
            String platformId = certificateCommonName.split(illegalSign)[1];
            if (platformId.equals(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID)) {
                return revokeAAMComponentUsingCertificate(certificate);
            }
            Platform platform = platformRepository.findOne(platformId);
            return revokePlatformComponentCertificateUsingCertificate(certificate, platform);
        }
        if (certificateCommonName.split(illegalSign).length == 3) {
            String username = certificateCommonName.split(illegalSign)[0];
            User user = userRepository.findOne(username);
            if (user == null) {
                throw new NotExistingUserException();
            }
            return revokeUserCertificateUsingCertificate(user, certificate);
        }
        throw new CertificateException();
    }

    private boolean revokeAAMComponentUsingCertificate(X509Certificate certificate) throws WrongCredentialsException, IOException, CertificateException {
        String componentId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
        ComponentCertificate componentCertificate = componentCertificatesRepository.findOne(componentId);
        if (componentCertificate == null
                || componentCertificate.getCertificate() == null
                || componentCertificate.getCertificate().getCertificateString().isEmpty()) {
            throw new WrongCredentialsException();
        }
        if (componentCertificate.getCertificate().getCertificateString().equals(CryptoHelper.convertX509ToPEM(certificate))) {
            revokeKey(componentId, componentCertificate.getCertificate());
            componentCertificatesRepository.delete(componentId);
            return true;
        }
        if (isRevoked(componentId, certificate.getPublicKey())) {
            return true;
        }
        throw new WrongCredentialsException();
    }

    public boolean revokeHomeTokenByAdmin(String token) throws ValidationException, MalformedJWTException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        if (JWTEngine.validateTokenString(token) != ValidationStatus.VALID) {
            throw new ValidationException("Invalid token");
        }
        JWTClaims tokenClaims = JWTEngine.getClaimsFromToken(token);
        if (!certificationAuthorityHelper.getAAMInstanceIdentifier().equals(tokenClaims.getIss())) {
            return false;
        }
        if (!tokenClaims.getIpk().equals(Base64.getEncoder().encodeToString(certificationAuthorityHelper.getAAMPublicKey().getEncoded()))) {
            return false;
        }
        revokedTokensRepository.save(new Token(token));
        return true;

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

    //Checking, if AAM certificate was revoked.
    /*
    private boolean isCertificateChainTrustedOrRevoked(String certificateString) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {
        if (!isCertificateChainTrusted(certificateString)){
            if (revokedKeysRepository.findOne(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID)!=null){
                X509Certificate certificate = CryptoHelper.convertPEMToX509(certificateString);
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
