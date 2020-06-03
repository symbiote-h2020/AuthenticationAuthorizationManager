package eu.h2020.symbiote.security.services;

import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ServiceManagementException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementResponse;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.SmartSpaceRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;

/**
 * Spring service used to manage platforms and their owners in the AAM repository.
 * <p>
 *
 * @author Maksymilian Marcinowski (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Profile("core")
@Service
public class PlatformsManagementService {

    private static final String GENERATED_PLATFORM_IDENTIFIER_PREFIX = "PLATFORM_";
    private final UserRepository userRepository;
    private final PlatformRepository platformRepository;
    private final SmartSpaceRepository smartSpaceRepository;
    private final PasswordEncoder passwordEncoder;
    private final RevokedKeysRepository revokedKeysRepository;
    private final AAMServices aamServices;

    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;

    @Value("${symbIoTe.core.interface.url}")
    private String coreInterfaceAddress;

    @Autowired
    public PlatformsManagementService(UserRepository userRepository,
                                      PlatformRepository platformRepository,
                                      SmartSpaceRepository smartSpaceRepository,
                                      PasswordEncoder passwordEncoder,
                                      RevokedKeysRepository revokedKeysRepository,
                                      AAMServices aamServices) {
        this.userRepository = userRepository;
        this.platformRepository = platformRepository;
        this.smartSpaceRepository = smartSpaceRepository;
        this.passwordEncoder = passwordEncoder;
        this.revokedKeysRepository = revokedKeysRepository;
        this.aamServices = aamServices;
    }

    public PlatformManagementResponse manage(PlatformManagementRequest platformManagementRequest) throws
            SecurityException {

        Credentials platformOwnerCredentials = platformManagementRequest.getPlatformOwnerCredentials();

        if (platformOwnerCredentials.getUsername().isEmpty() || platformOwnerCredentials.getPassword().isEmpty())
            throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_CREDENTIAL);

        if (!userRepository.existsById(platformOwnerCredentials.getUsername()))
            throw new NotExistingUserException();

        User platformOwner = userRepository.findById(platformOwnerCredentials.getUsername()).get();
        if (!platformOwnerCredentials.getPassword().equals(platformOwner.getPasswordEncrypted())
                && !passwordEncoder.matches(platformOwnerCredentials.getPassword(), platformOwner.getPasswordEncrypted())
                || !platformOwner.getRole().equals(UserRole.SERVICE_OWNER)) {
            throw new WrongCredentialsException();
        }

        // locked service owners can only cleanup their stuff
        if (platformOwner.getStatus() != AccountStatus.ACTIVE
                && platformManagementRequest.getOperationType() != OperationType.DELETE)
            throw new WrongCredentialsException(WrongCredentialsException.USER_NOT_ACTIVE, HttpStatus.FORBIDDEN);

        switch (platformManagementRequest.getOperationType()) {
            case CREATE:
                if (platformManagementRequest.getPlatformInterworkingInterfaceAddress().isEmpty())
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_PLATFORM_AAM_URL);
                if (platformManagementRequest.getPlatformInstanceFriendlyName().isEmpty())
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_INSTANCE_FRIENDLY_NAME);

                String platformId;
                // verify if platform owner provided a preferred platform identifier
                if (platformManagementRequest.getPlatformInstanceId().isEmpty()) {
                    // generate a new 'random' platform identifier
                    platformId = GENERATED_PLATFORM_IDENTIFIER_PREFIX + new Date().getTime();
                    platformManagementRequest.setPlatformInstanceId(platformId);
                }

                // check if platform already in repository
                if (platformRepository.existsById(platformManagementRequest.getPlatformInstanceId()))
                    throw new ServiceManagementException(ServiceManagementException.SERVICE_EXISTS, HttpStatus.BAD_REQUEST);

                if (platformManagementRequest.getPlatformInstanceId().equals(SecurityConstants.AAM_COMPONENT_NAME)
                        || platformManagementRequest.getPlatformInterworkingInterfaceAddress().equals(coreInterfaceAddress)
                        || !platformManagementRequest.getPlatformInstanceId().matches("^(([\\w-])+)$")
                        || platformManagementRequest.getPlatformInstanceId().startsWith(SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX))
                    // such a name would pose awkward questions
                    throw new ServiceManagementException(ServiceManagementException.AWKWARD_SERVICE, HttpStatus.BAD_REQUEST);

                // checking if Interworking interface isn't already used
                for (Platform platform : platformRepository.findAll()) {
                    if (platform.getPlatformInterworkingInterfaceAddress().equals(platformManagementRequest.getPlatformInterworkingInterfaceAddress())) {
                        throw new ServiceManagementException(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, HttpStatus.BAD_REQUEST);
                    }
                }
                for (SmartSpace smartSpace : smartSpaceRepository.findAll()) {
                    if (smartSpace.getExternalAddress().equals(platformManagementRequest.getPlatformInterworkingInterfaceAddress())) {
                        throw new ServiceManagementException(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, HttpStatus.BAD_REQUEST);
                    }
                }

                // use PO preferred platform identifier
                platformId = platformManagementRequest.getPlatformInstanceId();

                Platform platform = new Platform(platformId,
                        platformManagementRequest.getPlatformInterworkingInterfaceAddress(),
                        platformManagementRequest.getPlatformInstanceFriendlyName(),
                        platformOwner,
                        new Certificate(),
                        new HashMap<>());
                platformRepository.save(platform);
                platformOwner.getOwnedServices().add(platformId);
                userRepository.save(platformOwner);
                break;
            case UPDATE:
                platform = platformRepository.findById(platformManagementRequest.getPlatformInstanceId()).orElseGet(() -> null);
                if (platform == null)
                    throw new ServiceManagementException(ServiceManagementException.SERVICE_NOT_EXIST, HttpStatus.BAD_REQUEST);
                if (!platformOwner.getOwnedServices().contains(platformManagementRequest.getPlatformInstanceId())) {
                    throw new ServiceManagementException(ServiceManagementException.NOT_OWNED_SERVICE, HttpStatus.BAD_REQUEST);
                }
                if (!platformManagementRequest.getPlatformInstanceFriendlyName().isEmpty())
                    platform.setPlatformInstanceFriendlyName(platformManagementRequest.getPlatformInstanceFriendlyName());

                // II part
                if (!platformManagementRequest.getPlatformInterworkingInterfaceAddress().isEmpty()) {
                    // check if other platforms don't use that Interworking interface already
                    if (platformManagementRequest.getPlatformInterworkingInterfaceAddress().equals(coreInterfaceAddress))
                        throw new ServiceManagementException(ServiceManagementException.AWKWARD_SERVICE, HttpStatus.BAD_REQUEST);

                    // TODO try to improve it in R4 somehow
                    // checking if Interworking interface isn't already used
                    for (Platform platformInRepo : platformRepository.findAll()) {
                        // we check if some has the same II as the one passed
                        if (platformInRepo.getPlatformInterworkingInterfaceAddress().equals(platformManagementRequest.getPlatformInterworkingInterfaceAddress())
                                // and that is not us!
                                && !platformInRepo.getPlatformInstanceId().equals(platform.getPlatformInstanceId()))
                            throw new ServiceManagementException(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, HttpStatus.BAD_REQUEST);
                    }
                    for (SmartSpace smartSpace : smartSpaceRepository.findAll()) {
                        if (smartSpace.getExternalAddress().equals(platformManagementRequest.getPlatformInterworkingInterfaceAddress())) {
                            throw new ServiceManagementException(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, HttpStatus.BAD_REQUEST);
                        }
                    }
                    platform.setPlatformInterworkingInterfaceAddress(platformManagementRequest.getPlatformInterworkingInterfaceAddress());
                }
                platformRepository.save(platform);
                break;
            case DELETE:
                if (!platformRepository.existsById(platformManagementRequest.getPlatformInstanceId()))
                    throw new ServiceManagementException(ServiceManagementException.SERVICE_NOT_EXIST, HttpStatus.BAD_REQUEST);
                if (!platformOwner.getOwnedServices().contains(platformManagementRequest.getPlatformInstanceId())) {
                    throw new ServiceManagementException(ServiceManagementException.NOT_OWNED_SERVICE, HttpStatus.BAD_REQUEST);
                }
                Set<String> keys = new HashSet<>();
                try {
                    Platform platformForRemoval = platformRepository.findById(platformManagementRequest.getPlatformInstanceId()).get();
                    // adding platform AAM certificate for revocation
                    if (!platformForRemoval.getPlatformAAMCertificate().getCertificateString().isEmpty())
                        keys.add(Base64.getEncoder().encodeToString(
                                platformForRemoval.getPlatformAAMCertificate().getX509().getPublicKey().getEncoded()));

                    // checking if this key contains keys already
                    SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findById(platformForRemoval.getPlatformInstanceId()).orElseGet(() -> null);
                    if (subjectsRevokedKeys == null)
                        // no keys exist yet
                        revokedKeysRepository.save(new SubjectsRevokedKeys(platformForRemoval.getPlatformInstanceId(), keys));
                    else {
                        // extending the existing set
                        subjectsRevokedKeys.getRevokedKeysSet().addAll(keys);
                        revokedKeysRepository.save(subjectsRevokedKeys);
                    }
                } catch (CertificateException e) {
                    throw new ServiceManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
                }

                platformRepository.deleteById(platformManagementRequest.getPlatformInstanceId());
                // unbinding the platform from the platform owner
                platformOwner.getOwnedServices().remove(platformManagementRequest.getPlatformInstanceId());
                userRepository.save(platformOwner);
                break;
            default:
                throw new ServiceManagementException(ServiceManagementException.INVALID_OPERATION, HttpStatus.BAD_REQUEST);
        }

        aamServices.invalidateAvailableAAMsCache();
        aamServices.invalidateInternalAAMsCache();
        aamServices.invalidateComponentCertificateCache(SecurityConstants.AAM_COMPONENT_NAME, platformManagementRequest.getPlatformInstanceId());
        return new PlatformManagementResponse(platformManagementRequest.getPlatformInstanceId(), ManagementStatus.OK);
    }


    public PlatformManagementResponse authManage(PlatformManagementRequest request) throws
            SecurityException {
        // check if we received required credentials
        if (request.getAamOwnerCredentials() == null || request.getPlatformOwnerCredentials() == null)
            throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_CREDENTIALS);
        // check if this operation is authorized
        if (!request.getAamOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAamOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new WrongCredentialsException();
        return this.manage(request);
    }
}
