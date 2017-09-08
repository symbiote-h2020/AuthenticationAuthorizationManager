package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
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
    private final String adminUsername;
    private final String adminPassword;
    private IssuingAuthorityType deploymentType;

    @Autowired
    public UsersManagementService(UserRepository userRepository, RevokedKeysRepository revokedKeysRepository,
                                  CertificationAuthorityHelper certificationAuthorityHelper,
                                  PasswordEncoder passwordEncoder,
                                  @Value("${aam.deployment.owner.username}") String adminUsername,
                                  @Value("${aam.deployment.owner.password}") String adminPassword) throws
            SecurityMisconfigurationException {
        this.userRepository = userRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.passwordEncoder = passwordEncoder;
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;

        if (userRepository.exists(adminUsername) || SecurityConstants.GUEST_NAME.equals(adminUsername))
            throw new SecurityMisconfigurationException("AAM owner user already registered in database... Either delete that user or choose a different administrator username");
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

        User foundUser = userRepository.findOne(credentials.getUsername());
        // If requested user IS in database but wrong password was provided
        if (!credentials.getPassword().equals(foundUser.getPasswordEncrypted()) &&
                !passwordEncoder.matches(credentials.getPassword(), foundUser.getPasswordEncrypted()))
            throw new UserManagementException("Incorrect login / password", HttpStatus.UNAUTHORIZED);
        //  Everything is fine, returning requested user's details
        return new UserDetails(new Credentials(
                foundUser.getUsername(), ""),
                "",
                foundUser.getRecoveryMail(),
                foundUser.getRole(),
                foundUser.getAttributes(),
                foundUser.getClientCertificates()
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
        User userToManage = userRepository.findOne(userManagementRequest.getUserDetails().getCredentials().getUsername());
        switch (userManagementRequest.getOperationType()) {
            case CREATE:
                // validate request
                String newUserUsername = userDetails.getCredentials().getUsername();
                if (newUserUsername.isEmpty()
                        || userDetails.getCredentials().getPassword().isEmpty()) {
                    throw new InvalidArgumentsException("Missing username or password");
                }
                if (deploymentType == IssuingAuthorityType.CORE
                        && (userDetails.getRecoveryMail().isEmpty()))
                    // not used in R3
                    // || userDetails.getFederatedId().isEmpty()))
                    throw new InvalidArgumentsException("Missing recovery e-mail or OAuth identity");

                // verify proper user role
                if (userDetails.getRole() == UserRole.NULL)
                    throw new UserManagementException(HttpStatus.BAD_REQUEST);

                // check if user already in repository
                if (userRepository.exists(newUserUsername)) {
                    return ManagementStatus.USERNAME_EXISTS;
                }

                // blocking guest and AAMOwner registration
                if (adminUsername.equals(newUserUsername) || SecurityConstants.GUEST_NAME.equals(newUserUsername))
                    return ManagementStatus.ERROR;

                user.setRole(userDetails.getRole());
                user.setUsername(newUserUsername);
                user.setPasswordEncrypted(passwordEncoder.encode(userDetails.getCredentials().getPassword()));
                user.setRecoveryMail(userDetails.getRecoveryMail());
                user.setAttributes(userDetails.getAttributes());
                userRepository.save(user);
                break;
            case UPDATE:
                // checking if request contains current password
                if (!userManagementRequest.getUserCredentials().getPassword().equals(userToManage.getPasswordEncrypted())
                        && !passwordEncoder.matches(userManagementRequest.getUserCredentials().getPassword(), userToManage.getPasswordEncrypted()))
                    throw new UserManagementException(HttpStatus.UNAUTHORIZED);
                update(userManagementRequest, userToManage);
                break;

            case FORCE_UPDATE:
                update(userManagementRequest, userToManage);
                break;
            case ATTRIBUTES_UPDATE:
                userToManage.setAttributes(userDetails.getAttributes());
                userRepository.save(userToManage);
                break;
            case DELETE:
                delete(userManagementRequest.getUserDetails().getCredentials().getUsername());
                break;
        }
        return ManagementStatus.OK;
    }

    private void update(UserManagementRequest userManagementRequest, User user) {
        // update if not empty
        if (!userManagementRequest.getUserDetails().getCredentials().getPassword().isEmpty())
            user.setPasswordEncrypted(passwordEncoder.encode(userManagementRequest.getUserDetails().getCredentials().getPassword()));
        if (!userManagementRequest.getUserDetails().getRecoveryMail().isEmpty())
            user.setRecoveryMail(userManagementRequest.getUserDetails().getRecoveryMail());
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
