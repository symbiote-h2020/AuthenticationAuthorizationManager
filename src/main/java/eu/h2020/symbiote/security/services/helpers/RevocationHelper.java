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
import eu.h2020.symbiote.security.services.AAMServices;
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
    private final AAMServices aamServices;
    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;


    @Autowired
    public RevocationHelper(ComponentCertificatesRepository componentCertificatesRepository,
                            PlatformRepository platformRepository,
                            RevokedKeysRepository revokedKeysRepository,
                            RevokedTokensRepository revokedTokensRepository,
                            UserRepository userRepository,
                            CertificationAuthorityHelper certificationAuthorityHelper,
                            AAMServices aamServices) {
        this.componentCertificatesRepository = componentCertificatesRepository;
        this.platformRepository = platformRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.revokedTokensRepository = revokedTokensRepository;
        this.userRepository = userRepository;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.aamServices = aamServices;
    }

    private boolean revokeCertificateUsingCommonName(User user, String commonName) throws
            WrongCredentialsException,
            CertificateException {
        switch (commonName.split(illegalSign).length) {
            case 1:
                if (user.getRole() != UserRole.PLATFORM_OWNER || !user.getOwnedPlatforms().contains(commonName)) {
                    throw new SecurityException("User has no rights to this platform");
                }
                Platform platform = platformRepository.findOne(commonName);
                return revokePlatformCertificateUsingCommonName(commonName, platform);
            case 2:
                if (!commonName.split(illegalSign)[0].equals(user.getUsername())) {
                    throw new SecurityException("User has no rights to this client");
                }
                String clientId = commonName.split(illegalSign)[1];
                return revokeUserCertificateUsingCommonName(user, clientId);
            default:
                throw new WrongCredentialsException("Common name is wrong");
        }
    }

    private boolean revokeUserCertificateUsingCommonName(User user, String clientId) throws
            WrongCredentialsException,
            CertificateException {
        if (user.getClientCertificates().get(clientId) == null) {
            throw new WrongCredentialsException("Client doesn't exist");
        }
        if (user.getClientCertificates().get(clientId).getCertificateString().isEmpty()
                || !isMyCertificate(user.getClientCertificates().get(clientId).getX509())) {
            throw new CertificateException("Clients certificate is empty or issuer does not equals with this AAM");
        }
        revokeKey(user.getUsername(), user.getClientCertificates().get(clientId));
        user.getClientCertificates().remove(clientId);
        userRepository.save(user);
        return true;
    }

    private boolean revokePlatformCertificateUsingCommonName(String commonName, Platform platform) throws
            WrongCredentialsException,
            CertificateException {
        if (platform == null) {
            throw new WrongCredentialsException("There is no such platform");
        }
        if (platform.getPlatformAAMCertificate() == null
                || platform.getPlatformAAMCertificate().getCertificateString().isEmpty()
                || !isMyCertificate(platform.getPlatformAAMCertificate().getX509())) {
            throw new CertificateException("Platforms certificate is empty or issuer does not equals with this AAM");
        }
        revokeKey(commonName, platform.getPlatformAAMCertificate());
        platform.setPlatformAAMCertificate(new Certificate());
        platformRepository.save(platform);
        aamServices.deleteFromCacheInternalAAMs();
        aamServices.deleteFromCacheAvailableAAMs();
        aamServices.deleteFromCacheComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME, platform.getPlatformInstanceId());
        return true;
    }

    private boolean revokeCertificateUsingCertificate(User user, X509Certificate certificate) throws
            WrongCredentialsException,
            CertificateException,
            IOException {

        if (!isMyCertificate(certificate)) {
            throw new CertificateException("Issuer does not equals with this AAM");
        }
        if (certificate.getSubjectDN().getName().split("CN=").length != 2) {
            throw new CertificateException("Wrong structure of Subject item");
        }

        Set<String> ownedPlatforms = user.getOwnedPlatforms();
        switch (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign).length) {
            //revoking platform certificate
            case 1:
                if (user.getRole() != UserRole.PLATFORM_OWNER) {
                    throw new SecurityException("User is not the platform owner");
                }
                String platformId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
                if (!ownedPlatforms.contains(platformId)) {
                    throw new SecurityException("User is not the owner of the platform from certificate");
                }
                Platform platform = platformRepository.findOne(platformId);
                return revokePlatformCertificateUsingCertificate(certificate, platform);
            //revoking user certificate
            case 3:
                if (!certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0].equals(user.getUsername())) {
                    throw new WrongCredentialsException("User is not equal to user from CN");
                }
                return revokeUserCertificateUsingCertificate(user, certificate);
            default:
                throw new CertificateException("Wrong length of CN");

        }


    }

    private boolean isMyCertificate(X509Certificate certificate) {
        return certificate.getIssuerDN().getName().split("CN=")[1].contains(certificationAuthorityHelper.getAAMInstanceIdentifier());
    }

    private boolean revokeUserCertificateUsingCertificate(User user, X509Certificate certificate) throws
            CertificateException,
            WrongCredentialsException,
            IOException {
        String clientId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[1];
        if (user.getClientCertificates().get(clientId) == null
                || user.getClientCertificates().get(clientId).getCertificateString().isEmpty()) {
            throw new CertificateException("Client or his certificate doesn't exist");
        }
        //certificate to revoke is equal to this in db
        if (user.getClientCertificates().get(clientId).getCertificateString().equals(CryptoHelper.convertX509ToPEM(certificate))) {
            revokeKey(user.getUsername(), user.getClientCertificates().get(clientId));
            user.getClientCertificates().remove(clientId);
            userRepository.save(user);
            return true;
        }
        //key from certificate to revoke is already revoked
        if (isRevoked(user.getUsername(), certificate.getPublicKey())) {
            return true;
        }
        throw new WrongCredentialsException("Passed certificate do not equals with this in DB");
    }

    private boolean revokePlatformCertificateUsingCertificate(X509Certificate certificate, Platform platform) throws
            CertificateException,
            WrongCredentialsException,
            IOException {
        String platformId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
        if (platform == null) {
            throw new WrongCredentialsException("Platform doesn't exist");
        }
        if (platform.getPlatformAAMCertificate() == null
                || platform.getPlatformAAMCertificate().getCertificateString().isEmpty()) {
            throw new CertificateException("There is no certificate to revoke");
        }
        if (platform.getPlatformAAMCertificate().getCertificateString().equals(CryptoHelper.convertX509ToPEM(certificate))) {
            revokeKey(platformId, platform.getPlatformAAMCertificate());
            platform.setPlatformAAMCertificate(new Certificate());
            platformRepository.save(platform);
            aamServices.deleteFromCacheInternalAAMs();
            aamServices.deleteFromCacheAvailableAAMs();
            aamServices.deleteFromCacheComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME, platform.getPlatformInstanceId());
            return true;
        }
        if (isRevoked(platformId, certificate.getPublicKey())) {
            return true;
        }
        throw new WrongCredentialsException("Passed certificate do not equals with this in DB");
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
                throw new CertificateException("Error during conversion to X509Certificate occurred");
            }

            return revokeCertificateUsingCertificate(user, x509Certificate);
        }
        throw new CertificateException("Empty CN and cert");
    }

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

    private boolean isForeignTokenValid(Token foreignToken, Token remoteHomeToken) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            MalformedJWTException {
        JWTClaims remoteHomeTokenClaims = JWTEngine.getClaimsFromToken(remoteHomeToken.toString());
        JWTClaims foreignTokenClaims = JWTEngine.getClaimsFromToken(foreignToken.toString());
        if (!certificationAuthorityHelper.getAAMInstanceIdentifier().equals(foreignTokenClaims.getIss())) {
            return false;
        }
        if (!foreignTokenClaims.getIpk().equals(Base64.getEncoder().encodeToString(certificationAuthorityHelper.getAAMPublicKey().getEncoded()))) {
            return false;
        }
        if (remoteHomeToken.getClaims().getSubject().split(illegalSign).length != 2
                || foreignToken.getClaims().getSubject().split(illegalSign).length != 4) {
            return false;
        }
        if (!foreignTokenClaims.getSub().split(illegalSign)[0].equals(remoteHomeTokenClaims.getSub().split(illegalSign)[0])
                || !foreignTokenClaims.getSub().split(illegalSign)[1].equals(remoteHomeTokenClaims.getSub().split(illegalSign)[1])
                || !foreignTokenClaims.getSub().split(illegalSign)[2].equals(remoteHomeTokenClaims.getIss())
                || !foreignTokenClaims.getSub().split(illegalSign)[3].equals(remoteHomeTokenClaims.getJti())) {
            return false;
        }
        return foreignToken.getClaims().get("spk").equals(remoteHomeToken.getClaims().get("spk"));
    }

    public boolean revokeForeignToken(Token remoteHomeToken, Token foreignToken) throws
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            MalformedJWTException {

        if (isForeignTokenValid(foreignToken, remoteHomeToken)) {
            revokedTokensRepository.save(foreignToken);
            return true;
        }
        throw new IllegalArgumentException("Foreign token is invalid and does not mach remote Home Token");
    }

    public boolean revokeCertificateByAdmin(Certificate certificate, String certificateCommonName) throws
            WrongCredentialsException,
            CertificateException,
            IOException,
            NotExistingUserException {
        if (!certificateCommonName.isEmpty()) {
            switch (certificateCommonName.split(illegalSign).length) {
                case 1:
                    Platform platform = platformRepository.findOne(certificateCommonName);
                    return revokePlatformCertificateUsingCommonName(certificateCommonName, platform);
                case 2:
                    if (userRepository.exists(certificateCommonName.split(illegalSign)[0])) {
                        String username = certificateCommonName.split(illegalSign)[0];
                        String clientId = certificateCommonName.split(illegalSign)[1];
                        User user = userRepository.findOne(username);
                        if (user == null
                                || user.getClientCertificates().get(clientId) == null) {
                            throw new WrongCredentialsException("User or client doesn't exist");
                        }
                        return revokeUserCertificateUsingCommonName(user, clientId);
                    }
                    String componentId = certificateCommonName.split(illegalSign)[0];
                    String platformId = certificateCommonName.split(illegalSign)[1];
                    if (!platformId.equals(certificationAuthorityHelper.getAAMInstanceIdentifier())) {
                        throw new WrongCredentialsException("AAM can revoke only local components certificates");
                    }
                    return revokeLocalComponentUsingCommonName(componentId);
                default:
                    throw new WrongCredentialsException("Certificate common name is wrong");

            }


        }
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate and common name are empty");
        }

        X509Certificate x509Certificate;
        try {
            x509Certificate = certificate.getX509();
        } catch (Exception e) {
            throw new CertificateException("Error during conversion to X509Certificate occurred");
        }
        return revokeCertificateUsingCertificateByAdmin(x509Certificate);

    }

    private boolean revokeLocalComponentUsingCommonName(String componentId) throws
            CertificateException,
            WrongCredentialsException {
        ComponentCertificate componentCertificate = componentCertificatesRepository.findOne(componentId);
        if (componentCertificate == null
                || componentCertificate.getCertificate() == null
                || componentCertificate.getCertificate().getCertificateString().isEmpty()
                || !isMyCertificate(componentCertificate.getCertificate().getX509())) {
            throw new WrongCredentialsException("Component certificate is empty or issuer does not equals with this AAM");
        }
        revokeKey(componentId, componentCertificate.getCertificate());
        componentCertificatesRepository.delete(componentId);
        aamServices.deleteFromCacheInternalAAMs();
        aamServices.deleteFromCacheAvailableAAMs();
        aamServices.deleteFromCacheComponentCertificate(componentId, certificationAuthorityHelper.getAAMInstanceIdentifier());
        return true;
    }

    private boolean revokeCertificateUsingCertificateByAdmin(X509Certificate certificate) throws
            CertificateException,
            IOException,
            WrongCredentialsException,
            NotExistingUserException {
        if (!isMyCertificate(certificate)) {
            throw new CertificateException("Issuer does not equal with this AAM");
        }
        if (certificate.getSubjectDN().getName().split("CN=").length != 2) {
            throw new CertificateException("Wrong structure of Subject item");
        }
        String certificateCommonName = certificate.getSubjectDN().getName().split("CN=")[1];
        switch (certificateCommonName.split(illegalSign).length) {
            case 1:
                Platform platform = platformRepository.findOne(certificateCommonName);
                return revokePlatformCertificateUsingCertificate(certificate, platform);
            case 2:
                String platformId = certificateCommonName.split(illegalSign)[1];
                if (!platformId.equals(certificationAuthorityHelper.getAAMInstanceIdentifier())) {
                    throw new CertificateException("AAM can revoke only local components certificates");
                }
                return revokeLocalComponentUsingCertificate(certificate);
            case 3:
                String username = certificateCommonName.split(illegalSign)[0];
                User user = userRepository.findOne(username);
                if (user == null) {
                    throw new NotExistingUserException();
                }
                return revokeUserCertificateUsingCertificate(user, certificate);
            default:
                throw new CertificateException("Wrong length of certificates CN");
        }
    }

    private boolean revokeLocalComponentUsingCertificate(X509Certificate certificate) throws
            WrongCredentialsException,
            IOException,
            CertificateException {
        String componentId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
        ComponentCertificate componentCertificate = componentCertificatesRepository.findOne(componentId);
        if (componentCertificate == null
                || componentCertificate.getCertificate() == null
                || componentCertificate.getCertificate().getCertificateString().isEmpty()) {
            throw new WrongCredentialsException("There is no components certificate in DB");
        }
        if (componentCertificate.getCertificate().getCertificateString().equals(CryptoHelper.convertX509ToPEM(certificate))) {
            revokeKey(componentId, componentCertificate.getCertificate());
            componentCertificatesRepository.delete(componentId);
            aamServices.deleteFromCacheInternalAAMs();
            aamServices.deleteFromCacheAvailableAAMs();
            aamServices.deleteFromCacheComponentCertificate(componentId, certificationAuthorityHelper.getAAMInstanceIdentifier());
            return true;
        }
        if (isRevoked(componentId, certificate.getPublicKey())) {
            return true;
        }
        throw new WrongCredentialsException("Passed components certificate does not match this in DB");
    }

    public boolean revokeHomeTokenByAdmin(String token) throws
            ValidationException,
            MalformedJWTException,
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {
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
}
