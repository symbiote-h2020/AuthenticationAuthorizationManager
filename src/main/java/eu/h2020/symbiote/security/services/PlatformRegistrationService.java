package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.commons.Platform;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.RegistrationStatus;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import eu.h2020.symbiote.security.exceptions.custom.ExistingPlatformException;
import eu.h2020.symbiote.security.exceptions.custom.ExistingUserException;
import eu.h2020.symbiote.security.exceptions.custom.MissingArgumentsException;
import eu.h2020.symbiote.security.exceptions.custom.UnauthorizedRegistrationException;
import eu.h2020.symbiote.security.payloads.PlatformRegistrationRequest;
import eu.h2020.symbiote.security.payloads.PlatformRegistrationResponse;
import eu.h2020.symbiote.security.payloads.UserDetails;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * Spring service used to register platforms and their owners in the AAM repository.
 *
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class PlatformRegistrationService {

    private static final String GENERATED_PLATFORM_IDENTIFIER_PREFIX = "PLATFORM_";
    private final UserRepository userRepository;
    private final UserRegistrationService userRegistrationService;
    private final PlatformRepository platformRepository;

    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;
    private IssuingAuthorityType deploymentType;

    @Autowired
    public PlatformRegistrationService(UserRepository userRepository, UserRegistrationService
            userRegistrationService, PlatformRepository platformRepository, RegistrationManager registrationManager) {
        this.userRepository = userRepository;
        this.userRegistrationService = userRegistrationService;
        this.platformRepository = platformRepository;
        this.deploymentType = registrationManager.getDeploymentType();
    }

    public PlatformRegistrationResponse authRegister(PlatformRegistrationRequest request) throws
            SecurityException {

        // check if we received required credentials
        if (request.getAAMOwnerCredentials() == null || request.getPlatformOwnerDetails() == null || request
                .getPlatformOwnerDetails().getCredentials() == null)
            throw new MissingArgumentsException("Missing credentials");
        // check if this operation is authorized
        if (!request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAAMOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new UnauthorizedRegistrationException();
        return this.register(request);
    }

    public PlatformRegistrationResponse register(PlatformRegistrationRequest platformRegistrationRequest)
            throws SecurityException {

        UserDetails platformOwnerDetails = platformRegistrationRequest.getPlatformOwnerDetails();

        // validate request
        if (deploymentType == IssuingAuthorityType.CORE &&
                (platformOwnerDetails.getRecoveryMail()
                        .isEmpty() || platformOwnerDetails.getFederatedId().isEmpty()))
            throw new MissingArgumentsException("Missing recovery e-mail or federated identity");
        if (platformOwnerDetails.getCredentials().getUsername().isEmpty() || platformOwnerDetails.getCredentials()
                .getPassword().isEmpty())
            throw new MissingArgumentsException("Missing username or password");
        if (platformRegistrationRequest.getPlatformInterworkingInterfaceAddress().isEmpty())
            throw new MissingArgumentsException("Missing Platform AAM URL");
        if (platformRegistrationRequest.getPlatformInstanceFriendlyName().isEmpty())
            throw new MissingArgumentsException("Missing Platform Instance Friendly Name");

        // check if platform owner already in repository
        if (userRepository.exists(platformOwnerDetails.getCredentials().getUsername())) {
            throw new ExistingUserException();
        }


        String platformId;
        // verify if platform owner provided a preferred platform identifier
        if (platformRegistrationRequest.getPlatformInstanceId().isEmpty())
            // generate a new 'random' platform identifier
            platformId = GENERATED_PLATFORM_IDENTIFIER_PREFIX + new Date().getTime();
        else if (platformRepository.exists(platformRegistrationRequest.getPlatformInstanceId())) // check if platform
            // already
            // in repository
            throw new ExistingPlatformException();
        else {
            // use PO preferred platform identifier
            platformId = platformRegistrationRequest.getPlatformInstanceId();
        }

        // register platform owner in user repository
        userRegistrationService.authRegister(new UserRegistrationRequest(platformRegistrationRequest.getAAMOwnerCredentials(),
                        platformOwnerDetails));

        // register platform in repository
        // TODO R3 set the certificate from the received CSR.
        Platform platform = new Platform(platformId, platformRegistrationRequest
                .getPlatformInterworkingInterfaceAddress(),
                platformRegistrationRequest.getPlatformInstanceFriendlyName(), userRepository
                .findOne(platformOwnerDetails.getCredentials().getUsername()), new Certificate());
        platformRepository.save(platform);

        return new PlatformRegistrationResponse(platform.getPlatformInstanceId(), RegistrationStatus.OK);
    }

/*

    public void unregister(String username) throws NotExistingUserException, MissingArgumentsException {
        // validate request
        if (username.isEmpty())
            throw new MissingArgumentsException();
        // try-find user
        if (!userRepository.exists(username))
            throw new NotExistingUserException();
        // do it
        userRepository.delete(username);
    }

    public void authUnregister(UserRegistrationRequest request) throws MissingArgumentsException,
            NotExistingUserException, UnauthorizedUnregistrationException {

        // validate request
        if (request.getAdministratorCredentials() == null || request.getApplicationCredentials() == null)
            throw new MissingArgumentsException();
        // authorize
        if (!request.getAdministratorCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAdministratorCredentials().getPassword().equals(AAMOwnerPassword))
            throw new UnauthorizedUnregistrationException();
        // do it
        this.unregister(request.getApplicationCredentials().getUsername());
    }
    */
}
