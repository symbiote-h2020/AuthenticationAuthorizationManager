package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
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
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Maksymilian Marcinowski (PSNC)
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

    public ManagementStatus authManage(UserManagementRequest request) throws
            SecurityException {

        // check if we received required administrator credentials for API auth
        if (request.getAdministratorCredentials() == null || request.getUserDetails().getCredentials() == null)
            throw new InvalidArgumentsException();
        // and if they match the admin credentials from properties
        if (!request.getAdministratorCredentials().getUsername().equals(adminUsername)
                || !request.getAdministratorCredentials().getPassword().equals(adminPassword))
            throw new UserManagementException(HttpStatus.UNAUTHORIZED);
        // do it
        return this.manage(request);
    }

    public UserDetails getUserDetails(Credentials credentials) throws UserManagementException {
        //  If requested user is not in database
        if (!userRepository.exists(credentials.getUsername()))
            throw new UserManagementException("User not in database", HttpStatus.BAD_REQUEST);

        User held = userRepository.findOne(credentials.getUsername());
        // If requested user IS in database but wrong password was provided
        if (!credentials.getPassword().equals(held.getPasswordEncrypted()) &&
                !passwordEncoder.matches(credentials.getPassword(), held.getPasswordEncrypted()))
            throw new UserManagementException("Incorrect login / password", HttpStatus.UNAUTHORIZED);
        //  Everything is fine, returning requested user's details
        return new UserDetails(new Credentials(
                held.getUsername(), ""),
                "",
                held.getRecoveryMail(),
                held.getRole(),
                held.getAttributes()
        );
    }

    private ManagementStatus manage(UserManagementRequest userManagementRequest)
            throws SecurityException {
        UserDetails userDetails = userManagementRequest.getUserDetails();

        // Platform AAM does not support registering platform owners
        if (deploymentType == IssuingAuthorityType.PLATFORM
                && userDetails.getRole() != UserRole.USER)
            throw new InvalidArgumentsException();

        User user = new User();
        switch (userManagementRequest.getOperationType()) {
            case CREATE:
                // validate request
                if (userDetails.getCredentials().getUsername().isEmpty()
                        || userDetails.getCredentials().getPassword().isEmpty()) {
                    throw new InvalidArgumentsException("Missing username or password");
                }
                if (deploymentType == IssuingAuthorityType.CORE
                        && (userDetails.getRecoveryMail().isEmpty()
                        || userDetails.getFederatedId().isEmpty()))
                    throw new InvalidArgumentsException("Missing recovery e-mail or OAuth identity");

                // verify proper user role
                if (userDetails.getRole() == UserRole.NULL)
                    throw new UserManagementException(HttpStatus.BAD_REQUEST);

                // check if user already in repository
                if (userRepository.exists(userDetails.getCredentials().getUsername())) {
                    return ManagementStatus.USERNAME_EXISTS;
                }

                user.setRole(userDetails.getRole());
                user.setUsername(userDetails.getCredentials().getUsername());
                user.setPasswordEncrypted(passwordEncoder.encode(userDetails.getCredentials().getPassword()));
                user.setRecoveryMail(userDetails.getRecoveryMail());
                user.setAttributes(userDetails.getAttributes());
                userRepository.save(user);
                break;
            case UPDATE:
                update(userManagementRequest);
                break;
            case DELETE:
                delete(userManagementRequest.getUserDetails().getCredentials().getUsername());
                break;
        }
        return ManagementStatus.OK;
    }

    private void update(UserManagementRequest userManagementRequest) throws UserManagementException {
        User user = userRepository.findOne(userManagementRequest.getUserDetails().getCredentials().getUsername());
        // checking if request contains current password
        if (!userManagementRequest.getUserCredentials().getPassword().equals(user.getPasswordEncrypted())
                && !passwordEncoder.matches(userManagementRequest.getUserCredentials().getPassword(), user.getPasswordEncrypted()))
            throw new UserManagementException(HttpStatus.UNAUTHORIZED);

        // update if not empty
        if (!userManagementRequest.getUserDetails().getCredentials().getPassword().isEmpty())
            user.setPasswordEncrypted(passwordEncoder.encode(userManagementRequest.getUserDetails().getCredentials().getPassword()));
        if (!userManagementRequest.getUserDetails().getRecoveryMail().isEmpty())
            user.setRecoveryMail(userManagementRequest.getUserDetails().getRecoveryMail());
        user.setAttributes(userManagementRequest.getUserDetails().getAttributes());
        userRepository.save(user);
    }


    private void delete(String username) throws SecurityException {
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

            // checking if this key contains keys already
            SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(username);
            if (subjectsRevokedKeys == null)
                // no keys exist yet
                revokedKeysRepository.save(new SubjectsRevokedKeys(username, keys));
            else {
                // extending the existing set
                subjectsRevokedKeys.getRevokedKeysSet().addAll(keys);
                revokedKeysRepository.save(subjectsRevokedKeys);
            }
        } catch (CertificateException e) {
            log.error(e);
            throw new UserManagementException(e);
        }
        // do it
        userRepository.delete(username);
    }
}
