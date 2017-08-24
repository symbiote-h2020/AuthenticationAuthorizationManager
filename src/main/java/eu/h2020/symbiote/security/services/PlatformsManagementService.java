package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateException;
import java.util.*;

/**
 * Spring service used to manage platforms and their owners in the AAM repository.
 * <p>
 * @author Maksymilian Marcinowski (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class PlatformsManagementService {

    private static final String GENERATED_PLATFORM_IDENTIFIER_PREFIX = "PLATFORM_";
    private final UserRepository userRepository;
    private final PlatformRepository platformRepository;
    private final PasswordEncoder passwordEncoder;
    private final RevokedKeysRepository revokedKeysRepository;

    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;

    @Autowired
    public PlatformsManagementService(UserRepository userRepository, PlatformRepository platformRepository,
                                      PasswordEncoder passwordEncoder, RevokedKeysRepository revokedKeysRepository) {
        this.userRepository = userRepository;
        this.platformRepository = platformRepository;
        this.passwordEncoder = passwordEncoder;
        this.revokedKeysRepository = revokedKeysRepository;
    }

    public PlatformManagementResponse manage(PlatformManagementRequest platformManagementRequest) throws SecurityException {

        Credentials platformOwnerCredentials = platformManagementRequest.getPlatformOwnerCredentials();

        if (platformOwnerCredentials.getUsername().isEmpty() || platformOwnerCredentials.getPassword().isEmpty())
            throw new InvalidArgumentsException("Missing username or password");
        if (platformManagementRequest.getPlatformInterworkingInterfaceAddress().isEmpty())
            throw new InvalidArgumentsException("Missing Platform AAM URL");
        if (platformManagementRequest.getPlatformInstanceFriendlyName().isEmpty())
            throw new InvalidArgumentsException("Missing Platform Instance Friendly Name");

        if (!userRepository.exists(platformOwnerCredentials.getUsername()))
            throw new NotExistingUserException();

        User platformOwner = userRepository.findOne(platformOwnerCredentials.getUsername());
        if (!platformOwnerCredentials.getPassword().equals(platformOwner.getPasswordEncrypted())
                && !passwordEncoder.matches(platformOwnerCredentials.getPassword(), platformOwner.getPasswordEncrypted())) {
            throw new WrongCredentialsException();
        }


        switch (platformManagementRequest.getOperationType()) {
            case CREATE:
                String platformId;
                // verify if platform owner provided a preferred platform identifier
                if (platformManagementRequest.getPlatformInstanceId().isEmpty())
                    // generate a new 'random' platform identifier
                    platformId = GENERATED_PLATFORM_IDENTIFIER_PREFIX + new Date().getTime();
                else if (platformRepository.exists(platformManagementRequest.getPlatformInstanceId()))
                    // check if platform already in repository
                    throw new PlatformManagementException("Platform already exists", HttpStatus.BAD_REQUEST);
                else {
                    // use PO preferred platform identifier
                    platformId = platformManagementRequest.getPlatformInstanceId();
                }

                Platform platform = new Platform(platformId, platformManagementRequest
                        .getPlatformInterworkingInterfaceAddress(),
                        platformManagementRequest.getPlatformInstanceFriendlyName(), platformOwner, new Certificate(), new HashMap<>());
                platformRepository.save(platform);
                platformOwner.getOwnedPlatforms().put(platformId, platform);
                userRepository.save(platformOwner);
                break;

            case UPDATE:
                platform = platformRepository.findOne(platformManagementRequest.getPlatformInstanceId());
                if (platform == null)
                    throw new PlatformManagementException("Platform doesn't exist", HttpStatus.BAD_REQUEST);

                if (!platformManagementRequest.getPlatformInstanceFriendlyName().isEmpty())
                    platform.setPlatformInstanceFriendlyName(platformManagementRequest.getPlatformInstanceFriendlyName());
                if (!platformManagementRequest.getPlatformInterworkingInterfaceAddress().isEmpty())
                    platform.setPlatformInterworkingInterfaceAddress(platformManagementRequest.getPlatformInterworkingInterfaceAddress());

                platformRepository.save(platform);
                break;

            case DELETE:
                if (!platformRepository.exists(platformManagementRequest.getPlatformInstanceId()))
                    throw new PlatformManagementException("Platform doesn't exist", HttpStatus.BAD_REQUEST);
                Set<String> keys = new HashSet<>();
                try {
                    for (Certificate c : platformRepository.findOne(platformManagementRequest.getPlatformInstanceId())
                            .getComponentCertificates().values()) {
                        keys.add(Base64.getEncoder().encodeToString(
                                c.getX509().getPublicKey().getEncoded()));
                    }

                    // checking if this key contains keys already
                    SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(platformManagementRequest
                            .getPlatformOwnerCredentials().getUsername());
                    if (subjectsRevokedKeys == null)
                        // no keys exist yet
                        revokedKeysRepository.save(new SubjectsRevokedKeys(platformManagementRequest
                                .getPlatformOwnerCredentials().getUsername(), keys));
                    else {
                        // extending the existing set
                        subjectsRevokedKeys.getRevokedKeysSet().addAll(keys);
                        revokedKeysRepository.save(subjectsRevokedKeys);
                    }
                } catch (CertificateException e) {
                    throw new UserManagementException(e);
                }

                platformRepository.delete(platformManagementRequest.getPlatformInstanceId());
                break;
        }

        return new PlatformManagementResponse(platformManagementRequest.getPlatformInstanceId(), ManagementStatus.OK);
    }


    public PlatformManagementResponse authManage(PlatformManagementRequest request) throws
            SecurityException {

        // check if we received required credentials
        if (request.getAAMOwnerCredentials() == null || request.getPlatformOwnerCredentials() == null)
            throw new InvalidArgumentsException("Missing credentials");
        // check if this operation is authorized
        if (!request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAAMOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new WrongCredentialsException();
        return this.manage(request);
    }
}
