package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.commons.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.RegistrationStatus;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import eu.h2020.symbiote.security.exceptions.custom.*;
import eu.h2020.symbiote.security.payloads.UserDetails;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.rest.CoreServicesController;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * Spring service used to register users in the AAM repository.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class UserRegistrationService {
    private static Log log = LogFactory.getLog(UserRegistrationService.class);
    private final UserRepository userRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final RegistrationManager registrationManager;
    private final PasswordEncoder passwordEncoder;
    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;
    private IssuingAuthorityType deploymentType;

    @Autowired
    public UserRegistrationService(UserRepository userRepository, RevokedKeysRepository revokedKeysRepository, RegistrationManager registrationManager,
                                   PasswordEncoder passwordEncoder, CoreServicesController coreServicesController) {
        this.userRepository = userRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.registrationManager = registrationManager;
        this.passwordEncoder = passwordEncoder;
        this.deploymentType = registrationManager.getDeploymentType();
    }

    public RegistrationStatus register(UserRegistrationRequest userRegistrationRequest)
            throws SecurityException {

        UserDetails user = userRegistrationRequest.getUserDetails();

        // validate request
        if (deploymentType == IssuingAuthorityType.CORE &&
                (user.getRecoveryMail()
                        .isEmpty() || user.getFederatedId().isEmpty()))
            throw new MissingArgumentsException("Missing recovery e-mail or federated identity");
        if (user.getCredentials().getUsername().isEmpty() || user.getCredentials().getPassword().isEmpty()) {
            throw new MissingArgumentsException("Missing username or password");
        }
        // Platform AAM does not support registering platform owners
        if (deploymentType == IssuingAuthorityType.PLATFORM && user.getRole() != UserRole.APPLICATION)
            throw new UserRegistrationException();

        // check if user already in repository
        if (userRepository.exists(user.getCredentials().getUsername())) {
            return RegistrationStatus.USERNAME_EXISTS;
        }

        // verify proper user role
        if (user.getRole() == UserRole.NULL)
            throw new UserRegistrationException();


        Certificate certificate;
        String applicationPEMPrivateKey;

        try {
            // Generate key pair for the new user
            KeyPair applicationKeyPair = registrationManager.createKeyPair();

            // Generate PEM certificate for the user
            certificate = new Certificate(registrationManager.convertX509ToPEM
                    (registrationManager.createECCert(user.getCredentials().getUsername(),
                            applicationKeyPair.getPublic())));

            applicationPEMPrivateKey = registrationManager.convertPrivateKeyToPEM(applicationKeyPair
                    .getPrivate());

        } catch (NoSuchProviderException | NoSuchAlgorithmException | IOException |
                InvalidAlgorithmParameterException | UnrecoverableKeyException | OperatorCreationException |
                KeyStoreException | CertificateException e) {
            log.error(e);
            throw new UserRegistrationException(e);
        }

        // Register the user
        User application = new User();
        application.setRole(user.getRole());
        application.setUsername(user.getCredentials().getUsername());
        application.setPasswordEncrypted(passwordEncoder.encode(user.getCredentials().getPassword()));
        application.setRecoveryMail(user.getRecoveryMail());
        application.setCertificate(certificate);
        userRepository.save(application);

        return RegistrationStatus.OK;
    }

    public RegistrationStatus authRegister(UserRegistrationRequest request) throws
            SecurityException {

        // check if we received required credentials
        if (request.getAAMOwnerCredentials() == null || request.getUserDetails().getCredentials() == null)
            throw new MissingArgumentsException();
        // check if this operation is authorized
        if (!request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAAMOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new UnauthorizedRegistrationException();
        return this.register(request);
    }

    public void unregister(String username) throws SecurityException {
        // validate request
        if (username.isEmpty())
            throw new MissingArgumentsException();
        // try-find user
        if (!userRepository.exists(username))
            throw new NotExistingUserException();

        // add user certificated to revoked repository
        Set<String> keys = new HashSet<>();
        try {
            keys.add(Base64.getEncoder().encodeToString(
                    userRepository.findOne(username).getCertificate().getX509().getPublicKey().getEncoded()));
            revokedKeysRepository.save(new SubjectsRevokedKeys(username, keys));
        } catch (CertificateException e) {
            log.error(e);
            throw new UserRegistrationException(e);
        }
        // do it
        userRepository.delete(username);
    }

    public void authUnregister(UserRegistrationRequest request) throws SecurityException {

        // validate request
        if (request.getAAMOwnerCredentials() == null || request.getUserDetails().getCredentials() == null)
            throw new MissingArgumentsException();
        // authorize
        if (!request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAAMOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new UnauthorizedUnregistrationException();
        // do it
        this.unregister(request.getUserDetails().getCredentials().getUsername());
    }
}
