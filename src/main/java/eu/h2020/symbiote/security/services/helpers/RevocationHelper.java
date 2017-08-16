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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.security.cert.CertificateException;
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
    private static final Log log = LogFactory.getLog(RevocationHelper.class);


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

    // certificate revoke function - not finished
    //TODO exceptions to be changed, submetods to be added, still not verified and no tests
    public void revokeCertificate(Credentials credentials, Certificate certificate, String clientId)
            throws CertificateException, WrongCredentialsException, NotExistingUserException {
        // user public key revocation
        //TODO AAMadmin credentials check
        User user = userRepository.findOne(credentials.getUsername());
        if (user == null) {
            throw new NotExistingUserException();
        }
        if (passwordEncoder.matches(credentials.getPassword(), user.getPasswordEncrypted())) {
            if (clientId != null && !clientId.isEmpty()) {
                if (user.getClientCertificates().get(clientId) == null) {
                    throw new WrongCredentialsException();
                }
                revokeKey(user, user.getClientCertificates().get(clientId).getX509().getPublicKey());
                user.getClientCertificates().remove(clientId);
                userRepository.save(user);
            } else if (user.getRole() == UserRole.USER) {
                //checking CN structure
                if (certificate == null) {
                    throw new CertificateException();
                }
                if (certificate.getX509().getSubjectDN().getName().split("CN=").length != 2 || certificate.getX509().getSubjectDN().getName().split("CN=")[1].split(illegalSign).length != 3) {
                    throw new CertificateException();
                }
                if (user.getUsername().equals(certificate.getX509().getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0])) {
                    String clientIdFromCert = certificate.getX509().getSubjectDN().getName().split("CN=")[1].split(illegalSign)[1];
                    if (user.getClientCertificates().get(clientIdFromCert) != null) {
                        revokeKey(user, user.getClientCertificates().get(clientIdFromCert).getX509().getPublicKey());
                        user.getClientCertificates().remove(clientIdFromCert);
                        userRepository.save(user);
                    } else {
                        throw new CertificateException();
                    }
                } else {
                    throw new WrongCredentialsException();
                }
            } else if (user.getRole() == UserRole.PLATFORM_OWNER) {
                //checking CN structure
                if (certificate.getX509().getSubjectDN().getName().split("CN=").length != 2) {
                    throw new CertificateException();
                }
                if (!certificate.getX509().getSubjectDN().getName().contains(illegalSign)) {
                    String platformIdFromCert = certificate.getX509().getSubjectDN().getName().split("CN=")[1];
                    if (user.getClientCertificates().get(platformIdFromCert) != null) {
                        revokeKey(user, user.getClientCertificates().get(platformIdFromCert).getX509().getPublicKey());
                        user.getClientCertificates().remove(platformIdFromCert);
                        userRepository.save(user);
                    } else {
                        throw new CertificateException();
                    }
                } else {
                    String platformIdFromCert = certificate.getX509().getSubjectDN().getName().split("CN=")[1].split(illegalSign)[1];
                    String componentIdFromCert = certificate.getX509().getSubjectDN().getName().split("CN=")[1].split(illegalSign)[0];
                    if (platformRepository.findOne(platformIdFromCert) != null && platformRepository.findOne(platformIdFromCert).getComponentCertificates().get(componentIdFromCert) != null) {
                        Platform platform = platformRepository.findOne(platformIdFromCert);
                        revokeKey(user, user.getClientCertificates().get(componentIdFromCert).getX509().getPublicKey());
                        platformRepository.findOne(platformIdFromCert).getComponentCertificates().remove(componentIdFromCert);
                        platformRepository.save(platform);
                    } else {
                        throw new CertificateException();
                    }
                }
            } else {
                throw new SecurityException();
            }

        } else {
            throw new WrongCredentialsException();
        }
    }

    // token revokeHomeToken function - not finished
    //TODO @JT
    public void revokeHomeToken(Credentials credentials, Token token) throws CertificateException, WrongCredentialsException,
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
                if (Base64.getEncoder().encodeToString(user.getClientCertificates().entrySet().iterator()
                        .next().getValue().getX509().getPublicKey().getEncoded())
                        .equals(token.getClaims().get("spk"))) {
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

    //TODO @JT
    public void revokeForeignToken(Token remoteHomeToken, Token foreignToken) {
    }

    private void revokeKey(User user, PublicKey publicKey) {
        SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(user.getUsername());
        Set<String> keySet = (subjectsRevokedKeys == null) ? new HashSet<>() : subjectsRevokedKeys
                .getRevokedKeysSet();
        keySet.add(Base64.getEncoder().encodeToString(
                publicKey.getEncoded()));
        // adding key to revoked repository
        revokedKeysRepository.save(new SubjectsRevokedKeys(user.getUsername(), keySet));
    }
}
