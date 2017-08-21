package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.RevokedTokensRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

/**
 * Helper for revoking credentials.
 * TODO @Mikołaj fix to support tokens revocation by JTI
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
    private PlatformRepository platformRepository;
    private RevokedKeysRepository revokedKeysRepository;
    private RevokedTokensRepository revokedTokensRepository;
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;


    @Autowired
    public RevocationHelper(PlatformRepository platformRepository, RevokedKeysRepository revokedKeysRepository,
                            RevokedTokensRepository revokedTokensRepository, UserRepository userRepository,
                            PasswordEncoder passwordEncoder) {
        this.platformRepository = platformRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.revokedTokensRepository = revokedTokensRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    private boolean revokeCertificateUsingCommonName(User user, String commonName) throws WrongCredentialsException, CertificateException {
        if (commonName.split(illegalSign).length == 1) {
            if (user.getRole() == UserRole.PLATFORM_OWNER) {
                Platform platform = user.getOwnedPlatforms().get(commonName);
                if (platform == null) {
                    throw new WrongCredentialsException();
                }
                revokeKey(commonName, platform.getPlatformAAMCertificate());
                platform.setPlatformAAMCertificate(new Certificate());
                platformRepository.save(platform);
                return true;
            } else {
                throw new SecurityException();
            }
        } else if (commonName.split(illegalSign).length == 2) {
            if (commonName.split(illegalSign)[0].equals(user.getUsername())) {
                String clientId = commonName.split(illegalSign)[1];
                if (user.getClientCertificates().get(clientId) == null) {
                    throw new WrongCredentialsException();
                }
                revokeKey(user.getUsername(), user.getClientCertificates().get(clientId));
                user.getClientCertificates().remove(clientId);
                userRepository.save(user);
                return true;
            } else {
                if (user.getRole() == UserRole.PLATFORM_OWNER) {
                    String platformId = commonName.split(illegalSign)[1];
                    String componentId = commonName.split(illegalSign)[0];
                    Platform platform = user.getOwnedPlatforms().get(platformId);
                    if (platform == null || platform.getComponentCertificates().get(componentId) == null) {
                        throw new WrongCredentialsException();
                    }
                    revokeKey(platformId, platform.getComponentCertificates().get(componentId));
                    platform.getComponentCertificates().remove(componentId);
                    platformRepository.save(platform);
                    return true;
                } else {
                    throw new SecurityException();
                }
            }
        } else throw new WrongCredentialsException();
    }

    private boolean revokeCertificateUsingCertificate(User user, X509Certificate certificate) throws WrongCredentialsException, CertificateException {
        if (certificate.getSubjectDN().getName().split("CN=").length != 2) {
            throw new CertificateException();
        }
        if (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign).length == 1) {
            if (user.getRole() == UserRole.PLATFORM_OWNER) {
                String platformId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
                Platform platform = user.getOwnedPlatforms().get(platformId);
                if (platform != null) {
                    if (platform.getPlatformAAMCertificate() == null || platform.getPlatformAAMCertificate().getCertificateString().isEmpty()) {
                        throw new CertificateException();
                    }
                    if (platform.getPlatformAAMCertificate().getX509().getPublicKey() == certificate.getPublicKey()) {
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
            } else {
                throw new SecurityException();
            }
        } else if (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign).length == 2) {
            if (user.getRole() == UserRole.PLATFORM_OWNER) {
                String componentId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
                String platformId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[1];
                Platform platform = user.getOwnedPlatforms().get(platformId);
                if (platform != null && platform.getComponentCertificates().get(componentId) != null) {

                    if (platform.getComponentCertificates().get(componentId).getCertificateString().isEmpty()) {
                        throw new CertificateException();
                    }
                    if (platform.getComponentCertificates().get(componentId).getX509().getPublicKey() == certificate.getPublicKey()) {
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
            } else {
                throw new SecurityException();
            }
        } else if (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign).length == 3) {
            if (certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0].equals(user.getUsername())) {
                String clientId = certificate.getSubjectDN().getName().split("CN=")[1].split(illegalSign)[1];
                if (user.getClientCertificates().get(clientId) == null || user.getClientCertificates().get(clientId).getCertificateString().isEmpty()) {
                    throw new CertificateException();
                }
                if (user.getClientCertificates().get(clientId).getX509().getPublicKey() == certificate.getPublicKey()) {
                    revokeKey(user.getUsername(), user.getClientCertificates().get(clientId));
                    user.getClientCertificates().remove(clientId);
                    userRepository.save(user);
                    return true;
                } else if (isRevoked(user.getUsername(), certificate.getPublicKey())) {
                    return true;
                } else throw new WrongCredentialsException();

            } else {
                throw new WrongCredentialsException();
            }
        } else throw new CertificateException();
    }

    // certificate revoke function - not finished
    public boolean revokeCertificate(Credentials credentials, Certificate certificate, String commonName)
            throws CertificateException, WrongCredentialsException, NotExistingUserException {
        // user public key revocation
        //TODO AAMadmin credentials check
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
            } else if (certificate != null) {
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

    // token revokeHomeToken function - not finished
    //TODO @JT
    public boolean revokeHomeToken(Credentials credentials, Token token) throws CertificateException, WrongCredentialsException,
            NotExistingUserException, ValidationException {
        /* not sure that this needs to be here
        if (validate(token.getToken(), "") != ValidationStatus.VALID)
            throw new ValidationException("Invalid token");
        */
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
                if (platform != null && Base64.getEncoder().encodeToString(
                        platform.getPlatformAAMCertificate().getX509().getPublicKey().getEncoded())
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

    //TODO @JT
    public boolean revokeForeignToken(Token remoteHomeToken, Token foreignToken) {


        revokedTokensRepository.save(foreignToken);
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
}
