package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.certificate.CertificateHelper;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.RegistrationStatus;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import eu.h2020.symbiote.security.exceptions.custom.*;
import eu.h2020.symbiote.security.payloads.UserDetails;
import eu.h2020.symbiote.security.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
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
 * TODO @Mikołaj update to support full CRUD on users repo
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class UsersManagementService {
    private static Log log = LogFactory.getLog(UsersManagementService.class);
    private final UserRepository userRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final PasswordEncoder passwordEncoder;
    @Value("${aam.deployment.owner.username}")
    private String adminUsername;
    @Value("${aam.deployment.owner.password}")
    private String adminPassword;
    private IssuingAuthorityType deploymentType;

    @Autowired
    public UsersManagementService(UserRepository userRepository, RevokedKeysRepository revokedKeysRepository,
                                  CertificationAuthorityHelper certificationAuthorityHelper,
                                  PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.passwordEncoder = passwordEncoder;
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
    }

    public RegistrationStatus register(UserManagementRequest userManagementRequest)
            throws SecurityException {

        UserDetails userRegistrationDetails = userManagementRequest.getUserDetails();

        // validate request
        if (deploymentType == IssuingAuthorityType.CORE &&
                (userRegistrationDetails.getRecoveryMail()
                        .isEmpty() || userRegistrationDetails.getFederatedId().isEmpty()))
            throw new MissingArgumentsException("Missing recovery e-mail or federated identity");
        if (userRegistrationDetails.getCredentials().getUsername().isEmpty() || userRegistrationDetails
                .getCredentials().getPassword().isEmpty()) {
            throw new MissingArgumentsException("Missing username or password");
        }
        // Platform AAM does not support registering platform owners
        if (deploymentType == IssuingAuthorityType.PLATFORM && userRegistrationDetails.getRole() != UserRole.USER)
            throw new UserRegistrationException();

        // check if user already in repository
        if (userRepository.exists(userRegistrationDetails.getCredentials().getUsername())) {
            return RegistrationStatus.USERNAME_EXISTS;
        }

        // verify proper user role
        if (userRegistrationDetails.getRole() == UserRole.NULL)
            throw new UserRegistrationException();


        // TODO R3 drop as this is a separate step post registration
        Certificate certificate;
        try {
            // Generate key pair for the new user
            KeyPair userKeyPair = CertificateHelper.createKeyPair();

            // Generate PEM certificate for the user
            certificate = new Certificate(CertificateHelper.convertX509ToPEM
                    (certificationAuthorityHelper.createECCert(userRegistrationDetails.getCredentials().getUsername(),
                            userKeyPair.getPublic())));

        } catch (NoSuchProviderException | NoSuchAlgorithmException | IOException |
                InvalidAlgorithmParameterException | UnrecoverableKeyException | OperatorCreationException |
                KeyStoreException | CertificateException e) {
            log.error(e);
            throw new UserRegistrationException(e);
        }

        // Register the user
        User user = new User();
        user.setRole(userRegistrationDetails.getRole());
        user.setUsername(userRegistrationDetails.getCredentials().getUsername());
        user.setPasswordEncrypted(passwordEncoder.encode(userRegistrationDetails.getCredentials().getPassword()));
        user.setRecoveryMail(userRegistrationDetails.getRecoveryMail());
        // TODO R3 drop as this is a separate step
        user.setCertificate(certificate);
        userRepository.save(user);

        return RegistrationStatus.OK;
    }

    public RegistrationStatus authRegister(UserManagementRequest request) throws
            SecurityException {

        // check if we received required credentials
        if (request.getAdministratorCredentials() == null || request.getUserDetails().getCredentials() == null)
            throw new MissingArgumentsException();
        // check if this operation is authorized
        if (!request.getAdministratorCredentials().getUsername().equals(adminUsername)
                || !request.getAdministratorCredentials().getPassword().equals(adminPassword))
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

    public void authUnregister(UserManagementRequest request) throws SecurityException {

        // validate request
        if (request.getAdministratorCredentials() == null || request.getUserDetails().getCredentials() == null)
            throw new MissingArgumentsException();
        // authorize
        if (!request.getAdministratorCredentials().getUsername().equals(adminUsername)
                || !request.getAdministratorCredentials().getPassword().equals(adminPassword))
            throw new UnauthorizedUnregistrationException();
        // do it
        this.unregister(request.getUserDetails().getCredentials().getUsername());
    }
}
