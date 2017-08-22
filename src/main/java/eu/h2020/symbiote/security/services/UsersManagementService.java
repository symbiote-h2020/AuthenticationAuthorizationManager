package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * Spring service used to manage users in the AAM repository.
 * <p>
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
        this.passwordEncoder = passwordEncoder;
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
    }

    public ManagementStatus manage(UserManagementRequest userManagementRequest)
            throws SecurityException {
        UserDetails userRegistrationDetails = userManagementRequest.getUserDetails();

        // validate request
        if (deploymentType == IssuingAuthorityType.CORE &&
                (userRegistrationDetails.getRecoveryMail()
                        .isEmpty() || userRegistrationDetails.getFederatedId().isEmpty()))
            throw new InvalidArgumentsException("Missing recovery e-mail or foreign identity");
        if (userRegistrationDetails.getCredentials().getUsername().isEmpty() || userRegistrationDetails
                .getCredentials().getPassword().isEmpty()) {
            throw new InvalidArgumentsException("Missing username or password");
        }


        // Platform AAM does not support registering platform owners
        if (deploymentType == IssuingAuthorityType.PLATFORM && userRegistrationDetails.getRole() != UserRole.USER)
            throw new UserManagementException();


        // verify proper user role
        if (userRegistrationDetails.getRole() == UserRole.NULL)
            throw new UserManagementException();

        User user = new User();

        switch (userManagementRequest.getOperationType()) {
            case CREATE:
                user.setRole(userRegistrationDetails.getRole());
                user.setUsername(userRegistrationDetails.getCredentials().getUsername());
                user.setPasswordEncrypted(passwordEncoder.encode(userRegistrationDetails.getCredentials().getPassword()));
                user.setRecoveryMail(userRegistrationDetails.getRecoveryMail());
                userRepository.save(user);
                break;

            case UPDATE:
                user = userRepository.findOne(userManagementRequest.getUserDetails().getCredentials().getUsername());

                user.setPasswordEncrypted(passwordEncoder.encode(userManagementRequest.getUserDetails().getCredentials().getPassword()));
                user.setRecoveryMail(userManagementRequest.getUserDetails().getRecoveryMail());

                userRepository.save(user);
                break;

            case DELETE:
                delete(userManagementRequest.getUserDetails().getCredentials().getUsername());
                break;
        }
        return ManagementStatus.OK;
    }

    public ManagementStatus authRegister(UserManagementRequest request) throws
            SecurityException {

        // check if we received required credentials
        if (request.getAdministratorCredentials() == null || request.getUserDetails().getCredentials() == null)
            throw new InvalidArgumentsException();
        // check if this operation is authorized
        if (!request.getAdministratorCredentials().getUsername().equals(adminUsername)
                || !request.getAdministratorCredentials().getPassword().equals(adminPassword))
            throw new UserManagementException(HttpStatus.UNAUTHORIZED);
        return this.manage(request);
    }

    public void delete(String username) throws SecurityException {
        // validate request
        if (username.isEmpty())
            throw new InvalidArgumentsException();
        // try-find user
        if (!userRepository.exists(username))
            throw new NotExistingUserException();

        if (!userRepository.findOne(username).getOwnedPlatforms().isEmpty())
            throw new UserManagementException("Cannot remove platform owner with platforms", HttpStatus.BAD_REQUEST);

        // add user certificated to revoked repository
        Set<String> keys = new HashSet<>();
        try {
            for (Certificate c : userRepository.findOne(username).getClientCertificates().values()) {
                keys.add(Base64.getEncoder().encodeToString(
                        c.getX509().getPublicKey().getEncoded()));
            }

            revokedKeysRepository.save(new SubjectsRevokedKeys(username, keys));
        } catch (CertificateException e) {
            log.error(e);
            throw new UserManagementException(e);
        }
        // do it
        userRepository.delete(username);
    }

    public void authUnregister(UserManagementRequest request) throws SecurityException {

        // validate request
        if (request.getAdministratorCredentials() == null || request.getUserDetails().getCredentials() == null)
            throw new InvalidArgumentsException();
        // authorize
        if (!request.getAdministratorCredentials().getUsername().equals(adminUsername)
                || !request.getAdministratorCredentials().getPassword().equals(adminPassword))
            throw new UserManagementException(HttpStatus.UNAUTHORIZED);
        // do it
        this.delete(request.getUserDetails().getCredentials().getUsername());
    }
}
