package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ServiceManagementException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.SmartSpaceManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.SmartSpaceManagementResponse;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.SmartSpaceRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateException;
import java.util.*;

/**
 * Spring service used to manage smart spaces and their owners in the AAM repository.
 * <p>
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Profile("core")
@Service
public class SmartSpacesManagementService {

    private final UserRepository userRepository;
    private final SmartSpaceRepository smartSpaceRepository;
    private final PlatformRepository platformRepository;
    private final PasswordEncoder passwordEncoder;
    private final RevokedKeysRepository revokedKeysRepository;
    private final AAMServices aamServices;

    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;

    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    private String coreInterfaceAddress;

    @Autowired
    public SmartSpacesManagementService(UserRepository userRepository,
                                        SmartSpaceRepository smartSpaceRepository,
                                        PlatformRepository platformRepository,
                                        PasswordEncoder passwordEncoder,
                                        RevokedKeysRepository revokedKeysRepository,
                                        AAMServices aamServices) {
        this.userRepository = userRepository;
        this.smartSpaceRepository = smartSpaceRepository;
        this.platformRepository = platformRepository;
        this.passwordEncoder = passwordEncoder;
        this.revokedKeysRepository = revokedKeysRepository;
        this.aamServices = aamServices;
    }

    public SmartSpaceManagementResponse manage(SmartSpaceManagementRequest smartSpaceManagementRequest) throws
            SecurityException {

        Credentials smartSpaceOwnerCredentials = smartSpaceManagementRequest.getServiceOwnerCredentials();

        if (smartSpaceOwnerCredentials.getUsername().isEmpty() || smartSpaceOwnerCredentials.getPassword().isEmpty())
            throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_CREDENTIAL);

        if (!userRepository.exists(smartSpaceOwnerCredentials.getUsername()))
            throw new NotExistingUserException();

        User smartSpaceOwner = userRepository.findOne(smartSpaceOwnerCredentials.getUsername());
        if (!smartSpaceOwnerCredentials.getPassword().equals(smartSpaceOwner.getPasswordEncrypted())
                && !passwordEncoder.matches(smartSpaceOwnerCredentials.getPassword(), smartSpaceOwner.getPasswordEncrypted())
                || !smartSpaceOwner.getRole().equals(UserRole.SERVICE_OWNER)) {
            throw new WrongCredentialsException();
        }

        String smartSpaceId;

        switch (smartSpaceManagementRequest.getOperationType()) {
            case CREATE:
                if (smartSpaceManagementRequest.getInstanceFriendlyName().isEmpty())
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_INSTANCE_FRIENDLY_NAME);

                // verify if smart space owner provided a preferred smart space identifier
                if (smartSpaceManagementRequest.getInstanceId() == null
                        || smartSpaceManagementRequest.getInstanceId().isEmpty()) {
                    // generate a new 'random' smart space identifier
                    smartSpaceId = SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX + new Date().getTime();
                } else {
                    smartSpaceId = smartSpaceManagementRequest.getInstanceId();
                }
                if (!smartSpaceId.startsWith(SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX)) {
                    throw new InvalidArgumentsException(InvalidArgumentsException.NO_SSP_PREFIX);
                }

                // check if smart space is already in repository
                if (smartSpaceRepository.exists(smartSpaceId))
                    throw new ServiceManagementException(ServiceManagementException.SERVICE_EXISTS, HttpStatus.BAD_REQUEST);

                // checking if Gateway Address isn't already used
                if (!smartSpaceManagementRequest.getGatewayAddress().isEmpty()) {
                    for (SmartSpace smartSpace : smartSpaceRepository.findAll()) {
                        if (smartSpace.getGatewayAddress().equals(smartSpaceManagementRequest.getGatewayAddress()))
                            throw new ServiceManagementException(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, HttpStatus.BAD_REQUEST);
                    }
                    for (Platform platform : platformRepository.findAll()) {
                        if (platform.getPlatformInterworkingInterfaceAddress().equals(smartSpaceManagementRequest.getGatewayAddress()))
                            throw new ServiceManagementException(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, HttpStatus.BAD_REQUEST);
                    }
                }
                //smart space thanks to it's prefix can't have the same identifier as Core
                if (smartSpaceManagementRequest.getGatewayAddress().equals(coreInterfaceAddress)
                        || !smartSpaceId.matches("^(([\\w-])+)$"))
                    // such a name would pose awkward questions
                    throw new ServiceManagementException(ServiceManagementException.AWKWARD_SERVICE, HttpStatus.BAD_REQUEST);

                SmartSpace smartSpace = new SmartSpace(smartSpaceId,
                        smartSpaceManagementRequest.getGatewayAddress(),
                        smartSpaceManagementRequest.getSiteLocalAddress(),
                        smartSpaceManagementRequest.isExposingSiteLocalAddress(),
                        smartSpaceManagementRequest.getInstanceFriendlyName(),
                        new Certificate(),
                        new HashMap<>(),
                        smartSpaceOwner);
                smartSpaceRepository.save(smartSpace);
                smartSpaceOwner.getOwnedServices().add(smartSpaceId);
                userRepository.save(smartSpaceOwner);
                break;
            case UPDATE:
                smartSpaceId = smartSpaceManagementRequest.getInstanceId();
                smartSpace = smartSpaceRepository.findOne(smartSpaceId);
                if (smartSpace == null)
                    throw new ServiceManagementException(ServiceManagementException.SERVICE_NOT_EXIST, HttpStatus.BAD_REQUEST);
                if (!smartSpace.getSmartSpaceOwner().getUsername().equals(smartSpaceManagementRequest.getServiceOwnerCredentials().getUsername()))
                    throw new ServiceManagementException(ServiceManagementException.USER_IS_NOT_A_SERVICE_OWNER, HttpStatus.BAD_REQUEST);

                if (!smartSpaceManagementRequest.getInstanceFriendlyName().isEmpty())
                    smartSpace.setInstanceFriendlyName(smartSpaceManagementRequest.getInstanceFriendlyName());

                // check if other smart space don't use provided address already

                if (!smartSpaceManagementRequest.getGatewayAddress().isEmpty()
                        && !smartSpace.getGatewayAddress().equals(smartSpaceManagementRequest.getGatewayAddress())) {
                    for (SmartSpace smartSpaceRepo : smartSpaceRepository.findAll()) {
                        if (!smartSpaceRepo.getInstanceId().equals(smartSpace.getInstanceId())
                                && smartSpaceRepo.getGatewayAddress().equals(smartSpaceManagementRequest.getGatewayAddress()))
                            throw new ServiceManagementException(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, HttpStatus.BAD_REQUEST);
                    }
                    for (Platform platform : platformRepository.findAll()) {
                        if (platform.getPlatformInterworkingInterfaceAddress().equals(smartSpaceManagementRequest.getGatewayAddress()))
                            throw new ServiceManagementException(ServiceManagementException.SERVICE_ADDRESSES_IN_USE, HttpStatus.BAD_REQUEST);
                    }
                }
                smartSpace.setExposingSiteLocalAddress(smartSpaceManagementRequest.isExposingSiteLocalAddress());
                smartSpace.setGatewayAddress(smartSpaceManagementRequest.getGatewayAddress());
                smartSpace.setSiteLocalAddress(smartSpaceManagementRequest.getSiteLocalAddress());

                smartSpaceRepository.save(smartSpace);
                break;
            case DELETE:
                smartSpaceId = smartSpaceManagementRequest.getInstanceId();
                if (!smartSpaceRepository.exists(smartSpaceId))
                    throw new ServiceManagementException(ServiceManagementException.SERVICE_NOT_EXIST, HttpStatus.BAD_REQUEST);


                Set<String> keys = new HashSet<>();
                try {
                    SmartSpace smartSpaceForRemoval = smartSpaceRepository.findOne(smartSpaceId);
                    if (!smartSpaceForRemoval.getSmartSpaceOwner().getUsername().equals(smartSpaceManagementRequest.getServiceOwnerCredentials().getUsername()))
                        throw new ServiceManagementException(ServiceManagementException.USER_IS_NOT_A_SERVICE_OWNER, HttpStatus.BAD_REQUEST);
                    // adding smart space AAM certificate for revocation
                    if (!smartSpaceForRemoval.getAamCertificate().getCertificateString().isEmpty())
                        keys.add(Base64.getEncoder().encodeToString(
                                smartSpaceForRemoval.getAamCertificate().getX509().getPublicKey().getEncoded()));

                    // checking if this key contains keys already
                    SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(smartSpaceForRemoval.getInstanceId());
                    if (subjectsRevokedKeys == null)
                        // no keys exist yet
                        revokedKeysRepository.save(new SubjectsRevokedKeys(smartSpaceForRemoval.getInstanceId(), keys));
                    else {
                        // extending the existing set
                        subjectsRevokedKeys.getRevokedKeysSet().addAll(keys);
                        revokedKeysRepository.save(subjectsRevokedKeys);
                    }
                } catch (CertificateException e) {
                    throw new ServiceManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
                }

                smartSpaceRepository.delete(smartSpaceId);
                // unbinding the smart space from the service owner
                smartSpaceOwner.getOwnedServices().remove(smartSpaceId);
                userRepository.save(smartSpaceOwner);
                break;
            default:
                throw new ServiceManagementException(ServiceManagementException.INVALID_OPERATION, HttpStatus.BAD_REQUEST);
        }

        aamServices.invalidateAvailableAAMsCache();
        aamServices.invalidateInternalAAMsCache();
        aamServices.invalidateComponentCertificateCache(SecurityConstants.AAM_COMPONENT_NAME, smartSpaceId);
        return new SmartSpaceManagementResponse(smartSpaceId, ManagementStatus.OK);
    }


    public SmartSpaceManagementResponse authManage(SmartSpaceManagementRequest request) throws
            SecurityException {
        // check if we received required credentials
        if (request.getAamOwnerCredentials() == null || request.getServiceOwnerCredentials() == null)
            throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_CREDENTIALS);
        // check if this operation is authorized
        if (!request.getAamOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAamOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new WrongCredentialsException();
        return this.manage(request);
    }
}
