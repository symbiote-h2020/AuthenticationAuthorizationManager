package eu.h2020.symbiote.security.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UserManagementException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.communication.payloads.UserDetails;
import eu.h2020.symbiote.security.communication.payloads.UserManagementRequest;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
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
 */
@Service
public class UsersManagementService {

    @Value("${rabbit.queue.event}")
    private String anomalyDetectionQueue;
    @Value("${rabbit.routingKey.event}")
    private String anomalyDetectionRoutingKey;

    private static Log log = LogFactory.getLog(UsersManagementService.class);
    private final UserRepository userRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final PasswordEncoder passwordEncoder;
    private final String adminUsername;
    private final String adminPassword;
    private final IssuingAuthorityType deploymentType;

    private final RabbitTemplate rabbitTemplate;
    protected ObjectMapper mapper = new ObjectMapper();

    @Autowired
    public UsersManagementService(UserRepository userRepository, RevokedKeysRepository revokedKeysRepository,
                                  CertificationAuthorityHelper certificationAuthorityHelper,
                                  PasswordEncoder passwordEncoder, RabbitTemplate rabbitTemplate,
                                  @Value("${aam.deployment.owner.username}") String adminUsername,
                                  @Value("${aam.deployment.owner.password}") String adminPassword) throws
            SecurityMisconfigurationException {
        this.userRepository = userRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.passwordEncoder = passwordEncoder;
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.rabbitTemplate = rabbitTemplate;
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

    public UserDetails getUserDetails(Credentials credentials) throws UserManagementException, IOException {
        //  If requested user is not in database
        if (!userRepository.exists(credentials.getUsername()))
            throw new UserManagementException("User not in database", HttpStatus.BAD_REQUEST);

        User foundUser = userRepository.findOne(credentials.getUsername());
        // If requested user IS in database but wrong password was provided
        if (!credentials.getPassword().equals(foundUser.getPasswordEncrypted()) &&
                !passwordEncoder.matches(credentials.getPassword(), foundUser.getPasswordEncrypted())) {
            rabbitTemplate.convertAndSend(anomalyDetectionQueue, mapper.writeValueAsString(new EventLogRequest(credentials.getUsername(), null, null, EventType.LOGIN_FAILED, System.currentTimeMillis())));

            throw new UserManagementException("Incorrect login / password", HttpStatus.UNAUTHORIZED);
        }
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
    	
    	log.debug("Received a request for user management");
        UserDetails userDetails = userManagementRequest.getUserDetails();

        // Platform AAM does not support registering platform owners
        if (deploymentType == IssuingAuthorityType.PLATFORM
                && userDetails.getRole() != UserRole.USER) {
        	log.error("Platform AAM does not support registering platform owners");
            throw new InvalidArgumentsException();
        }

        User userToManage = userRepository.findOne(userManagementRequest.getUserDetails().getCredentials().getUsername());
        switch (userManagementRequest.getOperationType()) {
            case CREATE:
            	log.info("Request is a create request");
                // validate request
                String newUserUsername = userDetails.getCredentials().getUsername();
                if (!newUserUsername.matches("^(([\\w-])+)$")) {
                	log.error("Username "+newUserUsername+" contains invalid characters");
                    throw new InvalidArgumentsException("Could not create user with given Username");
                }
                if (newUserUsername.isEmpty()
                        || userDetails.getCredentials().getPassword().isEmpty()) {
                	log.error("Username or password is empty");
                    throw new InvalidArgumentsException("Missing username or password");
                }
                if (deploymentType == IssuingAuthorityType.CORE
                        && (userDetails.getRecoveryMail().isEmpty()))
                    // not used in R3
                    // || userDetails.getFederatedId().isEmpty()))
                {
                	log.error("Recovery information (email and OAuth) are both empty");
                    throw new InvalidArgumentsException("Missing recovery e-mail or OAuth identity");
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
                        userDetails.getAttributes(),
                        new HashSet<>()
                );
                userRepository.save(user);
                break;
            case UPDATE:
                if (userToManage == null)
                    throw new UserManagementException(HttpStatus.BAD_REQUEST);
                // checking if request contains current password
                if (!passwordEncoder.matches(userManagementRequest.getUserCredentials().getPassword(), userToManage.getPasswordEncrypted()))
                    throw new UserManagementException(HttpStatus.UNAUTHORIZED);
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

        User user = userRepository.findOne(username);
        if (user.getOwnedPlatforms() != null && !user.getOwnedPlatforms().isEmpty())
            throw new UserManagementException("Cannot remove platform owner with platforms", HttpStatus.BAD_REQUEST);

        // add user certificated to revoked repository
        Set<String> keys = new HashSet<>();
        try {
            for (Certificate c : user.getClientCertificates().values()) {
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
