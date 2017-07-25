package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.RegistrationStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ExistingPlatformException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.UnauthorizedRegistrationException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.communication.interfaces.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.interfaces.payloads.PlatformManagementResponse;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * Spring service used to register platforms and their owners in the AAM repository.
 *
 * TODO update to support full CRUD on platforms
 *
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class PlatformsManagementService {

    private static final String GENERATED_PLATFORM_IDENTIFIER_PREFIX = "PLATFORM_";
    private final UserRepository userRepository;
    private final UsersManagementService usersManagementService;
    private final PlatformRepository platformRepository;

    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;
    private IssuingAuthorityType deploymentType;

    @Autowired
    public PlatformsManagementService(UserRepository userRepository, UsersManagementService
            usersManagementService, PlatformRepository platformRepository, CertificationAuthorityHelper
                                              certificationAuthorityHelper) {
        this.userRepository = userRepository;
        this.usersManagementService = usersManagementService;
        this.platformRepository = platformRepository;
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
    }

    public PlatformManagementResponse authRegister(PlatformManagementRequest request) throws
            SecurityException {

        // check if we received required credentials
        if (request.getAAMOwnerCredentials() == null || request.getPlatformOwnerCredentials() == null)
            throw new MissingArgumentsException("Missing credentials");
        // check if this operation is authorized
        if (!request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAAMOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new UnauthorizedRegistrationException();
        return this.register(request);
    }

    public PlatformManagementResponse register(PlatformManagementRequest platformManagementRequest)
            throws SecurityException {

        Credentials platformOwnerCredentials = platformManagementRequest.getPlatformOwnerCredentials();

        if (platformOwnerCredentials.getUsername().isEmpty() || platformOwnerCredentials.getPassword().isEmpty())
            throw new MissingArgumentsException("Missing username or password");
        if (platformManagementRequest.getPlatformInterworkingInterfaceAddress().isEmpty())
            throw new MissingArgumentsException("Missing Platform AAM URL");
        if (platformManagementRequest.getPlatformInstanceFriendlyName().isEmpty())
            throw new MissingArgumentsException("Missing Platform Instance Friendly Name");

        // check if platform owner already in repository
        if (userRepository.exists(platformOwnerCredentials.getUsername())) {
            throw new ExistingUserException();
        }


        String platformId;
        // verify if platform owner provided a preferred platform identifier
        if (platformManagementRequest.getPlatformInstanceId().isEmpty())
            // generate a new 'random' platform identifier
            platformId = GENERATED_PLATFORM_IDENTIFIER_PREFIX + new Date().getTime();
        else if (platformRepository.exists(platformManagementRequest.getPlatformInstanceId())) // check if platform
            // already
            // in repository
            throw new ExistingPlatformException();
        else {
            // use PO preferred platform identifier
            platformId = platformManagementRequest.getPlatformInstanceId();
        }

        // register platform owner in user repository
        //usersManagementService.authRegister(new UserManagementRequest(platformManagementRequest
        //        .getAAMOwnerCredentials(),
        //                platformOwnerCredentials));

        // register platform in repository
        // TODO R3 set the certificate from the received CSR.
        Platform platform = new Platform(platformId, platformManagementRequest
                .getPlatformInterworkingInterfaceAddress(),
                platformManagementRequest.getPlatformInstanceFriendlyName(), userRepository
                .findOne(platformOwnerCredentials.getUsername()), new Certificate());
        platformRepository.save(platform);

        return new PlatformManagementResponse(platform.getPlatformInstanceId(), RegistrationStatus.OK);
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

    public void authUnregister(UserManagementRequest request) throws MissingArgumentsException,
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
