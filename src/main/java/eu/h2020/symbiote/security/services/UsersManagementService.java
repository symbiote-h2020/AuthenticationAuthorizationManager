package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
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
import java.util.HashMap;
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
 * @author Jakub Toczek (PSNC)
 */
@Service
public class UsersManagementService {
    private static Log log = LogFactory.getLog(UsersManagementService.class);
    private final UserRepository userRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final PasswordEncoder passwordEncoder;
    private final String adminUsername;
    private final String adminPassword;
    private final IssuingAuthorityType deploymentType;

    @Autowired
    public UsersManagementService(UserRepository userRepository,
                                  RevokedKeysRepository revokedKeysRepository,
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
            throw new SecurityMisconfigurationException(SecurityMisconfigurationException.AAM_OWNER_USER_ALREADY_REGISTERED);
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
            throw new UserManagementException(UserManagementException.USER_NOT_IN_DATABASE, HttpStatus.BAD_REQUEST);

        User foundUser = userRepository.findOne(credentials.getUsername());
        // If requested user IS in database but wrong password was provided
        if (!credentials.getPassword().equals(foundUser.getPasswordEncrypted()) &&
                !passwordEncoder.matches(credentials.getPassword(), foundUser.getPasswordEncrypted()))
            throw new UserManagementException(UserManagementException.INCORRECT_LOGIN_PASSWORD, HttpStatus.UNAUTHORIZED);
        //  Everything is fine, returning requested user's details
        return new UserDetails(new Credentials(
                foundUser.getUsername(), ""),
                foundUser.getRecoveryMail(),
                foundUser.getRole(),
                foundUser.getStatus(),
                foundUser.getAttributes(),
                foundUser.getClientCertificates()
        );
    }

    private ManagementStatus manage(UserManagementRequest userManagementRequest)
            throws SecurityException {
    	
    	log.debug("Received a request for user management");
        UserDetails userDetails = userManagementRequest.getUserDetails();

        // CORE and SMART_SPACE AAM support registering platform owners
        switch (deploymentType) {
            case CORE:
            case SMART_SPACE:
                if (userDetails.getRole() == UserRole.NULL
                        && userManagementRequest.getOperationType().equals(OperationType.CREATE)) {
                    log.error("This AAM does not support registration of users with this role.");
                    throw new InvalidArgumentsException();
                }
                break;
            case NULL:
            case PLATFORM:
                if (userDetails.getRole() != UserRole.USER
                        && userManagementRequest.getOperationType().equals(OperationType.CREATE)) {
                    log.error("This AAM does not support registration of users with this role.");
                    throw new InvalidArgumentsException();
                }
        }

        User userToManage = userRepository.findOne(userManagementRequest.getUserDetails().getCredentials().getUsername());
        switch (userManagementRequest.getOperationType()) {
            case CREATE:
            	log.info("Request is a create request");
                // validate request
                String newUserUsername = userDetails.getCredentials().getUsername();
                if (!newUserUsername.matches("^(([\\w-])+)$")) {
                	log.error("Username "+newUserUsername+" contains invalid characters");
                    throw new InvalidArgumentsException(InvalidArgumentsException.COULD_NOT_CREATE_USER_WITH_GIVEN_USERNAME);
                }
                if (newUserUsername.isEmpty()
                        || userDetails.getCredentials().getPassword().isEmpty()) {
                	log.error("Username or password is empty");
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_CREDENTIAL);
                }
                if (deploymentType == IssuingAuthorityType.CORE
                        && (userDetails.getRecoveryMail().isEmpty()))
                    // not used in R3
                    // || userDetails.getFederatedId().isEmpty()))
                {
                	log.error("Recovery information (email and OAuth) are both empty");
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_RECOVERY_E_MAIL_OR_OAUTH_IDENTITY);
                }

                // verify proper user role 
                if (userDetails.getRole() == UserRole.NULL) {
                	log.error("User Role is null");
                    throw new UserManagementException(HttpStatus.BAD_REQUEST);
                }

                // check if user already in repository
                if (userRepository.exists(newUserUsername)) {
                	log.error("Username "+newUserUsername+" already exists");
                    return ManagementStatus.USERNAME_EXISTS;
                }

                // blocking guest and AAMOwner registration, and aam component
                if (adminUsername.equals(newUserUsername) || SecurityConstants.GUEST_NAME.equals(newUserUsername) || SecurityConstants.AAM_COMPONENT_NAME.equals(newUserUsername)) {
                	log.error("Username "+newUserUsername+" would override a predefined username");
                    return ManagementStatus.ERROR;
                }

                User user = new User(newUserUsername,
                        passwordEncoder.encode(userDetails.getCredentials().getPassword()),
                        userDetails.getRecoveryMail(),
                        new HashMap<>(),
                        userDetails.getRole(),
                        userDetails.getStatus(),
                        userDetails.getAttributes(),
                        new HashSet<>()
                );
                userRepository.save(user);
                break;
            case UPDATE:
                if (userToManage == null)
                    throw new UserManagementException(HttpStatus.BAD_REQUEST);
                // checking if request contains validation credentials equal to those provided in user details
                if (!userManagementRequest.getUserCredentials().getUsername().equals(userToManage.getUsername()))
                    throw new UserManagementException(HttpStatus.BAD_REQUEST);
                // checking if request contains current password
                if (!passwordEncoder.matches(userManagementRequest.getUserCredentials().getPassword(), userToManage.getPasswordEncrypted()))
                    throw new UserManagementException(HttpStatus.UNAUTHORIZED);
                //TODO ignore status change, only admin can change it!
                update(userManagementRequest, userToManage);
                break;
            case FORCE_UPDATE:
                if (userToManage == null)
                    throw new UserManagementException(HttpStatus.BAD_REQUEST);
                update(userManagementRequest, userToManage);
                break;
            case ATTRIBUTES_UPDATE:
                if (userToManage == null)
                    throw new UserManagementException(HttpStatus.BAD_REQUEST);
                userToManage.setAttributes(userDetails.getAttributes());
                userRepository.save(userToManage);
                break;
            case DELETE:
                delete(userToManage);
                break;
        }
        return ManagementStatus.OK;
    }

    private void update(UserManagementRequest userManagementRequest,
                        User user) {
        // update if not empty
        if (!userManagementRequest.getUserDetails().getCredentials().getPassword().isEmpty())
            user.setPasswordEncrypted(passwordEncoder.encode(userManagementRequest.getUserDetails().getCredentials().getPassword()));
        if (!userManagementRequest.getUserDetails().getRecoveryMail().isEmpty())
            user.setRecoveryMail(userManagementRequest.getUserDetails().getRecoveryMail());
        user.setStatus(userManagementRequest.getUserDetails().getStatus());
        userRepository.save(user);
    }


    private void delete(User userToManage) throws
            SecurityException {

        // check if user was found
        if (userToManage == null)
            throw new NotExistingUserException();

        if (userToManage.getOwnedServices() != null && !userToManage.getOwnedServices().isEmpty())
            throw new UserManagementException(UserManagementException.CANNOT_REMOVE_SERVICE_OWNER_WITH_SERVICES, HttpStatus.BAD_REQUEST);

        // add user certificated to revoked repository
        Set<String> keys = new HashSet<>();
        try {
            for (Certificate c : userToManage.getClientCertificates().values()) {
                keys.add(Base64.getEncoder().encodeToString(
                        c.getX509().getPublicKey().getEncoded()));
            }

            // checking if this key contains keys already
            SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(userToManage.getUsername());
            if (subjectsRevokedKeys == null)
                // no keys exist yet
                revokedKeysRepository.save(new SubjectsRevokedKeys(userToManage.getUsername(), keys));
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
        userRepository.delete(userToManage.getUsername());
    }
}
