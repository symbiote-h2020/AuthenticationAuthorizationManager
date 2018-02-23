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
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.SmartSpaceRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
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
                                        PasswordEncoder passwordEncoder,
                                        RevokedKeysRepository revokedKeysRepository,
                                        AAMServices aamServices) {
        this.userRepository = userRepository;
        this.smartSpaceRepository = smartSpaceRepository;
        this.passwordEncoder = passwordEncoder;
        this.revokedKeysRepository = revokedKeysRepository;
        this.aamServices = aamServices;
    }

    public SmartSpaceManagementResponse manage(SmartSpaceManagementRequest smartSpaceManagementRequest) throws
            SecurityException {

        Credentials smartSpaceOwnerCredentials = smartSpaceManagementRequest.getServiceOwnerCredentials();

        if (smartSpaceOwnerCredentials.getUsername().isEmpty() || smartSpaceOwnerCredentials.getPassword().isEmpty())
            throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_USERNAME_OR_PASSWORD);

        if (!userRepository.exists(smartSpaceOwnerCredentials.getUsername()))
            throw new NotExistingUserException();

        User smartSpaceOwner = userRepository.findOne(smartSpaceOwnerCredentials.getUsername());
        if (!smartSpaceOwnerCredentials.getPassword().equals(smartSpaceOwner.getPasswordEncrypted())
                && !passwordEncoder.matches(smartSpaceOwnerCredentials.getPassword(), smartSpaceOwner.getPasswordEncrypted())
                || !smartSpaceOwner.getRole().equals(UserRole.SERVICE_OWNER)) {
            throw new WrongCredentialsException();
        }
        if (smartSpaceManagementRequest.getGatewayAddress() == null) {
            smartSpaceManagementRequest.setGatewayAddress("");
        }
        if (smartSpaceManagementRequest.getSiteLocalAddress() == null) {
            smartSpaceManagementRequest.setSiteLocalAddress("");
        }

        switch (smartSpaceManagementRequest.getOperationType()) {
            case CREATE:
                if (smartSpaceManagementRequest.getGatewayAddress().isEmpty()
                        && smartSpaceManagementRequest.getSiteLocalAddress().isEmpty())
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_INTERWORKING_INTERFACES);

                if (smartSpaceManagementRequest.getInstanceFriendlyName().isEmpty())
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_INSTANCE_FRIENDLY_NAME);

                String smartSpaceId;
                // verify if smart space owner provided a preferred smart space identifier
                if (smartSpaceManagementRequest.getInstanceId() == null
                        || smartSpaceManagementRequest.getInstanceId().isEmpty()) {
                    // generate a new 'random' smart space identifier
                    smartSpaceId = SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX + new Date().getTime();
                    smartSpaceManagementRequest.setInstanceId(smartSpaceId);
                }
                if (!smartSpaceManagementRequest.getInstanceId().startsWith(SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX)) {
                    throw new InvalidArgumentsException(InvalidArgumentsException.NO_SSP_PREFIX);
                }

                // check if smart space is already in repository
                if (smartSpaceRepository.exists(smartSpaceManagementRequest.getInstanceId()))
                    throw new ServiceManagementException(ServiceManagementException.SERVICE_EXISTS, HttpStatus.BAD_REQUEST);

                // TODO try to improve it in R4 somehow
                // checking if Interworking interface isn't already used
                String usedInterworkingAddress = smartSpaceManagementRequest.isExposingSiteLocalAddress() ?
                        smartSpaceManagementRequest.getSiteLocalAddress() : smartSpaceManagementRequest.getGatewayAddress();
                if (usedInterworkingAddress.isEmpty()) {
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_EXPOSED_INTERWORKING_INTERFACE);
                }
                for (SmartSpace smartSpace : smartSpaceRepository.findAll()) {
                    String usedInterworkingAddressRepo = smartSpace.isExposingSiteLocalAddress() ?
                            smartSpace.getSiteLocalAddress() : smartSpace.getGatewayAddress();
                    if (usedInterworkingAddressRepo.equals(usedInterworkingAddress))
                        throw new ServiceManagementException(ServiceManagementException.SERVICE_INTERWORKING_INTERFACE_IN_USE, HttpStatus.BAD_REQUEST);
                }

                if (smartSpaceManagementRequest.getInstanceId().equals(SecurityConstants.AAM_COMPONENT_NAME)
                        || usedInterworkingAddress.equals(coreInterfaceAddress)
                        || !smartSpaceManagementRequest.getInstanceId().matches("^(([\\w-])+)$"))
                    // such a name would pose awkward questions
                    throw new ServiceManagementException(ServiceManagementException.AWKWARD_SERVICE, HttpStatus.BAD_REQUEST);

                // use SO preferred smart space identifier
                smartSpaceId = smartSpaceManagementRequest.getInstanceId();

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
                smartSpace = smartSpaceRepository.findOne(smartSpaceManagementRequest.getInstanceId());
                if (smartSpace == null)
                    throw new ServiceManagementException(ServiceManagementException.SERVICE_NOT_EXIST, HttpStatus.BAD_REQUEST);
                if (!smartSpace.getSmartSpaceOwner().getUsername().equals(smartSpaceManagementRequest.getServiceOwnerCredentials().getUsername()))
                    throw new ServiceManagementException(ServiceManagementException.USER_IS_NOT_A_SERVICE_OWNER, HttpStatus.BAD_REQUEST);

                if (!smartSpaceManagementRequest.getInstanceFriendlyName().isEmpty())
                    smartSpace.setInstanceFriendlyName(smartSpaceManagementRequest.getInstanceFriendlyName());

                // II part
                if (!smartSpaceManagementRequest.getGatewayAddress().isEmpty()
                        || !smartSpaceManagementRequest.getSiteLocalAddress().isEmpty()
                        || smartSpace.isExposingSiteLocalAddress() != smartSpaceManagementRequest.isExposingSiteLocalAddress()) {

                    usedInterworkingAddress = smartSpaceManagementRequest.isExposingSiteLocalAddress() ?
                            smartSpaceManagementRequest.getSiteLocalAddress() : smartSpaceManagementRequest.getGatewayAddress();

                    if (usedInterworkingAddress.isEmpty()) {
                        throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_EXPOSED_INTERWORKING_INTERFACE);
                    }

                    if (smartSpaceManagementRequest.isExposingSiteLocalAddress()
                            && smartSpaceManagementRequest.getSiteLocalAddress().isEmpty())
                        throw new InvalidArgumentsException("When you want to expose internal interworking interface, it should be provided");


                    // check if other smart space don't use that Interworking interface already
                    for (SmartSpace smartSpaceRepo : smartSpaceRepository.findAll()) {
                        String usedInterworkingAddressRepo = smartSpaceRepo.isExposingSiteLocalAddress() ?
                                smartSpaceRepo.getSiteLocalAddress() : smartSpaceRepo.getGatewayAddress();
                        if (usedInterworkingAddressRepo.equals(usedInterworkingAddress) &&
                                !smartSpaceRepo.getInstanceId().equals(smartSpace.getInstanceId()))
                            throw new ServiceManagementException(ServiceManagementException.SERVICE_INTERWORKING_INTERFACE_IN_USE, HttpStatus.BAD_REQUEST);
                    }

                    smartSpace.setExposingSiteLocalAddress(smartSpaceManagementRequest.isExposingSiteLocalAddress());
                    smartSpace.setGatewayAddress(smartSpaceManagementRequest.getGatewayAddress());
                    smartSpace.setSiteLocalAddress(smartSpaceManagementRequest.getSiteLocalAddress());
                }
                smartSpaceRepository.save(smartSpace);
                break;
            case DELETE:
                if (!smartSpaceRepository.exists(smartSpaceManagementRequest.getInstanceId()))
                    throw new ServiceManagementException(ServiceManagementException.SERVICE_NOT_EXIST, HttpStatus.BAD_REQUEST);


                Set<String> keys = new HashSet<>();
                try {
                    SmartSpace smartSpaceForRemoval = smartSpaceRepository.findOne(smartSpaceManagementRequest.getInstanceId());
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

                smartSpaceRepository.delete(smartSpaceManagementRequest.getInstanceId());
                // unbinding the smart space from the platform owner
                smartSpaceOwner.getOwnedServices().remove(smartSpaceManagementRequest.getInstanceId());
                userRepository.save(smartSpaceOwner);
                break;
            default:
                throw new ServiceManagementException(ServiceManagementException.INVALID_OPERATION, HttpStatus.BAD_REQUEST);
        }

        aamServices.invalidateAvailableAAMsCache();
        aamServices.invalidateInternalAAMsCache();
        aamServices.invalidateComponentCertificateCache(SecurityConstants.AAM_COMPONENT_NAME, smartSpaceManagementRequest.getInstanceId());
        return new SmartSpaceManagementResponse(smartSpaceManagementRequest.getInstanceId(), ManagementStatus.OK);
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
