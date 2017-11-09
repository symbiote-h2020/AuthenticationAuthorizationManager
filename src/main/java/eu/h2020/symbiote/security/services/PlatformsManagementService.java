package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.PlatformManagementException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
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
 *
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

    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    private String coreInterfaceAddress;

    @Autowired
    public PlatformsManagementService(UserRepository userRepository, PlatformRepository platformRepository,
                                      PasswordEncoder passwordEncoder, RevokedKeysRepository revokedKeysRepository) {
        this.userRepository = userRepository;
        this.platformRepository = platformRepository;
        this.passwordEncoder = passwordEncoder;
        this.revokedKeysRepository = revokedKeysRepository;
    }

    public PlatformManagementResponse manage(PlatformManagementRequest platformManagementRequest) throws
            SecurityException, CertificateException {

        Credentials platformOwnerCredentials = platformManagementRequest.getPlatformOwnerCredentials();

        if (platformOwnerCredentials.getUsername().isEmpty() || platformOwnerCredentials.getPassword().isEmpty())
            throw new InvalidArgumentsException("Missing username or password");

        if (!userRepository.exists(platformOwnerCredentials.getUsername()))
            throw new NotExistingUserException();

        User platformOwner = userRepository.findOne(platformOwnerCredentials.getUsername());
        if (!platformOwnerCredentials.getPassword().equals(platformOwner.getPasswordEncrypted())
                && !passwordEncoder.matches(platformOwnerCredentials.getPassword(), platformOwner.getPasswordEncrypted())) {
            throw new WrongCredentialsException();
        }

        switch (platformManagementRequest.getOperationType()) {
            case CREATE:
                if (platformManagementRequest.getPlatformInterworkingInterfaceAddress().isEmpty())
                    throw new InvalidArgumentsException("Missing Platform AAM URL");
                if (platformManagementRequest.getPlatformInstanceFriendlyName().isEmpty())
                    throw new InvalidArgumentsException("Missing Platform Instance Friendly Name");

                String platformId;
                // verify if platform owner provided a preferred platform identifier
                if (platformManagementRequest.getPlatformInstanceId().isEmpty()) {
                    // generate a new 'random' platform identifier
                    platformId = GENERATED_PLATFORM_IDENTIFIER_PREFIX + new Date().getTime();
                    platformManagementRequest.setPlatformInstanceId(platformId);
                }

                // check if platform already in repository
                if (platformRepository.exists(platformManagementRequest.getPlatformInstanceId()))
                    throw new PlatformManagementException("Platform already exists", HttpStatus.BAD_REQUEST);

                // TODO try to improve it in R4 somehow
                // checking if Interworking interface isn't already used
                for (Platform platform : platformRepository.findAll()) {
                    if (platform.getPlatformInterworkingInterfaceAddress().equals(platformManagementRequest.getPlatformInterworkingInterfaceAddress()))
                        throw new PlatformManagementException("Platform interworking interface already in use", HttpStatus.BAD_REQUEST);
                }

                if (platformManagementRequest.getPlatformInstanceId().equals(SecurityConstants.AAM_COMPONENT_NAME)
                        || platformManagementRequest.getPlatformInterworkingInterfaceAddress().equals(coreInterfaceAddress)
                        || !platformManagementRequest.getPlatformInstanceId().matches("^(([\\w-])+)$"))
                    // such a name would pose awkward questions
                    throw new PlatformManagementException("That is an awkward platform, we won't register it", HttpStatus.BAD_REQUEST);

                // use PO preferred platform identifier
                platformId = platformManagementRequest.getPlatformInstanceId();

                Platform platform = new Platform(platformId,
                        platformManagementRequest.getPlatformInterworkingInterfaceAddress(),
                        platformManagementRequest.getPlatformInstanceFriendlyName(),
                        platformOwner,
                        new Certificate(),
                        new HashMap<>());
                platformRepository.save(platform);
                platformOwner.getOwnedPlatforms().add(platformId);
                userRepository.save(platformOwner);
                break;
            case UPDATE:
                platform = platformRepository.findOne(platformManagementRequest.getPlatformInstanceId());
                if (platform == null)
                    throw new PlatformManagementException("Platform doesn't exist", HttpStatus.BAD_REQUEST);

                if (!platformManagementRequest.getPlatformInstanceFriendlyName().isEmpty())
                    platform.setPlatformInstanceFriendlyName(platformManagementRequest.getPlatformInstanceFriendlyName());

                // II part
                if (!platformManagementRequest.getPlatformInterworkingInterfaceAddress().isEmpty()) {
                    // check if other platforms don't use that Interworking interface already
                    if (platformManagementRequest.getPlatformInterworkingInterfaceAddress().equals(coreInterfaceAddress))
                        throw new PlatformManagementException("That is an awkward platform interface, we won't update it", HttpStatus.BAD_REQUEST);

                    // TODO try to improve it in R4 somehow
                    // checking if Interworking interface isn't already used
                    List<Platform> platformsInRepo = platformRepository.findAll();
                    platformsInRepo.remove(platform);
                    for (Platform otherPlatform : platformsInRepo) {
                        if (otherPlatform.getPlatformInterworkingInterfaceAddress().equals(platformManagementRequest.getPlatformInterworkingInterfaceAddress()))
                            throw new PlatformManagementException("Platform interworking interface already in use", HttpStatus.BAD_REQUEST);
                    }
                    platform.setPlatformInterworkingInterfaceAddress(platformManagementRequest.getPlatformInterworkingInterfaceAddress());
                }
                platformRepository.save(platform);
                break;
            case DELETE:
                if (!platformRepository.exists(platformManagementRequest.getPlatformInstanceId()))
                    throw new PlatformManagementException("Platform doesn't exist", HttpStatus.BAD_REQUEST);
                Set<String> keys = new HashSet<>();
                try {
                    Platform platformForRemoval = platformRepository.findOne(platformManagementRequest.getPlatformInstanceId());
                    // adding platform AAM certificate for revocation
                    if (!platformForRemoval.getPlatformAAMCertificate().getCertificateString().isEmpty())
                        keys.add(Base64.getEncoder().encodeToString(
                                platformForRemoval.getPlatformAAMCertificate().getX509().getPublicKey().getEncoded()));

                    // checking if this key contains keys already
                    SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(platformForRemoval.getPlatformInstanceId());
                    if (subjectsRevokedKeys == null)
                        // no keys exist yet
                        revokedKeysRepository.save(new SubjectsRevokedKeys(platformForRemoval.getPlatformInstanceId(), keys));
                    else {
                        // extending the existing set
                        subjectsRevokedKeys.getRevokedKeysSet().addAll(keys);
                        revokedKeysRepository.save(subjectsRevokedKeys);
                    }
                } catch (CertificateException e) {
                    throw new PlatformManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
                }

                platformRepository.delete(platformManagementRequest.getPlatformInstanceId());
                // unbinding the platform from the platform owner
                platformOwner.getOwnedPlatforms().remove(platformManagementRequest.getPlatformInstanceId());
                userRepository.save(platformOwner);
                break;
            default:
                throw new PlatformManagementException("Invalid operation", HttpStatus.BAD_REQUEST);
        }

        return new PlatformManagementResponse(platformManagementRequest.getPlatformInstanceId(), ManagementStatus.OK);
    }


    public PlatformManagementResponse authManage(PlatformManagementRequest request) throws
            SecurityException,
            CertificateException {
        // check if we received required credentials
        if (request.getAamOwnerCredentials() == null || request.getPlatformOwnerCredentials() == null)
            throw new InvalidArgumentsException("Missing credentials");
        // check if this operation is authorized
        if (!request.getAamOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAamOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new WrongCredentialsException();
        return this.manage(request);
    }
}
