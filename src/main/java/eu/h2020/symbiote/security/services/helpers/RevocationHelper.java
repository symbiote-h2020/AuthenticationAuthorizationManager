package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
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
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

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

    private static Log log = LogFactory.getLog(RevocationHelper.class);
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


    // certificate revoke function - not finished
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
                Set<String> keySet = (subjectsRevokedKeys == null) ? new HashSet<>() : subjectsRevokedKeys
                        .getRevokedKeysSet();
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

    // token revoke function - not finished
    public void revoke(Credentials credentials, Token token) throws CertificateException, WrongCredentialsException,
            NotExistingUserException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            KeyStoreException, IOException, ValidationException {
        /* not sure that this needs to be here
        if (validate(token.getToken(), "") != ValidationStatus.VALID)
            throw new ValidationException("Invalid token");
        */
        // user token revocation
        User user = userRepository.findOne(credentials.getUsername());
        if (user != null) {
            if (passwordEncoder.matches(credentials.getPassword(), user.getPasswordEncrypted())) {
                // user
                if (Base64.getEncoder().encodeToString(user.getCertificate().getX509().getPublicKey().getEncoded())
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

}
