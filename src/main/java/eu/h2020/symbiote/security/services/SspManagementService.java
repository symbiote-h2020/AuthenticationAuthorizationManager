package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SspManagementException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.SspManagementRequest;
import eu.h2020.symbiote.security.communication.payloads.SspManagementResponse;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.SspRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.Ssp;
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
 * Spring service used to manage ssp and their owners in the AAM repository.
 * <p>
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Profile("core")
@Service
public class SspManagementService {

    private final UserRepository userRepository;
    private final SspRepository sspRepository;
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
    public SspManagementService(UserRepository userRepository,
                                SspRepository sspRepository,
                                PasswordEncoder passwordEncoder,
                                RevokedKeysRepository revokedKeysRepository,
                                AAMServices aamServices) {
        this.userRepository = userRepository;
        this.sspRepository = sspRepository;
        this.passwordEncoder = passwordEncoder;
        this.revokedKeysRepository = revokedKeysRepository;
        this.aamServices = aamServices;
    }

    public SspManagementResponse manage(SspManagementRequest sspManagementRequest) throws
            SecurityException {

        Credentials sspOwnerCredentials = sspManagementRequest.getSspOwnerCredentials();

        if (sspOwnerCredentials.getUsername().isEmpty() || sspOwnerCredentials.getPassword().isEmpty())
            throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_USERNAME_OR_PASSWORD);

        if (!userRepository.exists(sspOwnerCredentials.getUsername()))
            throw new NotExistingUserException();

        User sspOwner = userRepository.findOne(sspOwnerCredentials.getUsername());
        if (!sspOwnerCredentials.getPassword().equals(sspOwner.getPasswordEncrypted())
                && !passwordEncoder.matches(sspOwnerCredentials.getPassword(), sspOwner.getPasswordEncrypted())
                || !sspOwner.getRole().equals(UserRole.SSP_OWNER)) {
            throw new WrongCredentialsException();
        }
        if (sspManagementRequest.getSspExternalInterworkingInterfaceAddress() == null) {
            sspManagementRequest.setSspExternalInterworkingInterfaceAddress("");
        }
        if (sspManagementRequest.getSspInternalInterworkingInterfaceAddress() == null) {
            sspManagementRequest.setSspInternalInterworkingInterfaceAddress("");
        }

        switch (sspManagementRequest.getOperationType()) {
            case CREATE:
                if (sspManagementRequest.getSspExternalInterworkingInterfaceAddress().isEmpty()
                        && sspManagementRequest.getSspInternalInterworkingInterfaceAddress().isEmpty())
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_INTERWORKING_INTERFACES);

                if (sspManagementRequest.getSspInstanceFriendlyName().isEmpty())
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_INSTANCE_FRIENDLY_NAME);

                String sspId;
                // verify if ssp owner provided a preferred ssp identifier
                if (sspManagementRequest.getSspInstanceId() == null
                        || sspManagementRequest.getSspInstanceId().isEmpty()) {
                    // generate a new 'random' ssp identifier
                    sspId = SecurityConstants.SSP_IDENTIFIER_PREFIX + new Date().getTime();
                    sspManagementRequest.setSspInstanceId(sspId);
                }
                if (!sspManagementRequest.getSspInstanceId().startsWith(SecurityConstants.SSP_IDENTIFIER_PREFIX)) {
                    throw new InvalidArgumentsException(InvalidArgumentsException.NO_SSP_PREFIX);
                }

                // check if ssp already in repository
                if (sspRepository.exists(sspManagementRequest.getSspInstanceId()))
                    throw new SspManagementException(SspManagementException.SSP_EXISTS, HttpStatus.BAD_REQUEST);

                // TODO try to improve it in R4 somehow
                // checking if Interworking interface isn't already used
                String usedInterworkingAddress = sspManagementRequest.isExposedInternalInterworkingInterfaceAddress() ?
                        sspManagementRequest.getSspInternalInterworkingInterfaceAddress() : sspManagementRequest.getSspExternalInterworkingInterfaceAddress();
                if (usedInterworkingAddress.isEmpty()) {
                    throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_EXPOSED_INTERWORKING_INTERFACE);
                }
                for (Ssp ssp : sspRepository.findAll()) {
                    String usedInterworkingAddressRepo = ssp.isExposedInternalInterworkingInterfaceAddress() ?
                            ssp.getSspInternalInterworkingInterfaceAddress() : ssp.getSspExternalInterworkingInterfaceAddress();
                    if (usedInterworkingAddressRepo.equals(usedInterworkingAddress))
                        throw new SspManagementException(SspManagementException.SSP_INTERWARKING_INTERFACE_IN_USE, HttpStatus.BAD_REQUEST);
                }

                if (sspManagementRequest.getSspInstanceId().equals(SecurityConstants.AAM_COMPONENT_NAME)
                        || usedInterworkingAddress.equals(coreInterfaceAddress)
                        || !sspManagementRequest.getSspInstanceId().matches("^(([\\w-])+)$"))
                    // such a name would pose awkward questions
                    throw new SspManagementException(SspManagementException.AWKWARD_SSP, HttpStatus.BAD_REQUEST);

                // use SO preferred ssp identifier
                sspId = sspManagementRequest.getSspInstanceId();

                Ssp ssp = new Ssp(sspId,
                        sspManagementRequest.getSspExternalInterworkingInterfaceAddress(),
                        sspManagementRequest.getSspInternalInterworkingInterfaceAddress(),
                        sspManagementRequest.isExposedInternalInterworkingInterfaceAddress(),
                        sspManagementRequest.getSspInstanceFriendlyName(),
                        new Certificate(),
                        new HashMap<>(),
                        sspOwner);
                sspRepository.save(ssp);
                sspOwner.getOwnedServices().add(sspId);
                userRepository.save(sspOwner);
                break;
            case UPDATE:
                ssp = sspRepository.findOne(sspManagementRequest.getSspInstanceId());
                if (ssp == null)
                    throw new SspManagementException(SspManagementException.SSP_NOT_EXIST, HttpStatus.BAD_REQUEST);
                if (!ssp.getSspOwner().getUsername().equals(sspManagementRequest.getSspOwnerCredentials().getUsername()))
                    throw new SspManagementException(SspManagementException.USER_IS_NOT_A_SSP_OWNER, HttpStatus.BAD_REQUEST);

                if (!sspManagementRequest.getSspInstanceFriendlyName().isEmpty())
                    ssp.setSspInstanceFriendlyName(sspManagementRequest.getSspInstanceFriendlyName());

                // II part
                if (!sspManagementRequest.getSspExternalInterworkingInterfaceAddress().isEmpty()
                        || !sspManagementRequest.getSspInternalInterworkingInterfaceAddress().isEmpty()
                        || ssp.isExposedInternalInterworkingInterfaceAddress() != sspManagementRequest.isExposedInternalInterworkingInterfaceAddress()) {

                    usedInterworkingAddress = sspManagementRequest.isExposedInternalInterworkingInterfaceAddress() ?
                            sspManagementRequest.getSspInternalInterworkingInterfaceAddress() : sspManagementRequest.getSspExternalInterworkingInterfaceAddress();

                    if (usedInterworkingAddress.isEmpty()) {
                        throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_EXPOSED_INTERWORKING_INTERFACE);
                    }

                    if (sspManagementRequest.isExposedInternalInterworkingInterfaceAddress()
                            && sspManagementRequest.getSspInternalInterworkingInterfaceAddress().isEmpty())
                        throw new InvalidArgumentsException("When you want to expose internal interworking interface, it should be provided");


                    // check if other ssp don't use that Interworking interface already
                    for (Ssp sspRepo : sspRepository.findAll()) {
                        String usedInterworkingAddressRepo = sspRepo.isExposedInternalInterworkingInterfaceAddress() ?
                                sspRepo.getSspInternalInterworkingInterfaceAddress() : sspRepo.getSspExternalInterworkingInterfaceAddress();
                        if (usedInterworkingAddressRepo.equals(usedInterworkingAddress) &&
                                !sspRepo.getSspInstanceId().equals(ssp.getSspInstanceId()))
                            throw new SspManagementException(SspManagementException.SSP_INTERWARKING_INTERFACE_IN_USE, HttpStatus.BAD_REQUEST);
                    }

                    ssp.setExposedInternalInterworkingInterfaceAddress(sspManagementRequest.isExposedInternalInterworkingInterfaceAddress());
                    ssp.setSspExternalInterworkingInterfaceAddress(sspManagementRequest.getSspExternalInterworkingInterfaceAddress());
                    ssp.setSspInternalInterworkingInterfaceAddress(sspManagementRequest.getSspInternalInterworkingInterfaceAddress());
                }
                sspRepository.save(ssp);
                break;
            case DELETE:
                if (!sspRepository.exists(sspManagementRequest.getSspInstanceId()))
                    throw new SspManagementException(SspManagementException.SSP_NOT_EXIST, HttpStatus.BAD_REQUEST);


                Set<String> keys = new HashSet<>();
                try {
                    Ssp sspForRemoval = sspRepository.findOne(sspManagementRequest.getSspInstanceId());
                    if (!sspForRemoval.getSspOwner().getUsername().equals(sspManagementRequest.getSspOwnerCredentials().getUsername()))
                        throw new SspManagementException(SspManagementException.USER_IS_NOT_A_SSP_OWNER, HttpStatus.BAD_REQUEST);
                    // adding ssp AAM certificate for revocation
                    if (!sspForRemoval.getSspAAMCertificate().getCertificateString().isEmpty())
                        keys.add(Base64.getEncoder().encodeToString(
                                sspForRemoval.getSspAAMCertificate().getX509().getPublicKey().getEncoded()));

                    // checking if this key contains keys already
                    SubjectsRevokedKeys subjectsRevokedKeys = revokedKeysRepository.findOne(sspForRemoval.getSspInstanceId());
                    if (subjectsRevokedKeys == null)
                        // no keys exist yet
                        revokedKeysRepository.save(new SubjectsRevokedKeys(sspForRemoval.getSspInstanceId(), keys));
                    else {
                        // extending the existing set
                        subjectsRevokedKeys.getRevokedKeysSet().addAll(keys);
                        revokedKeysRepository.save(subjectsRevokedKeys);
                    }
                } catch (CertificateException e) {
                    throw new SspManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
                }

                sspRepository.delete(sspManagementRequest.getSspInstanceId());
                // unbinding the ssp from the platform owner
                sspOwner.getOwnedServices().remove(sspManagementRequest.getSspInstanceId());
                userRepository.save(sspOwner);
                break;
            default:
                throw new SspManagementException(SspManagementException.INVALID_OPERATION, HttpStatus.BAD_REQUEST);
        }

        aamServices.deleteFromCacheAvailableAAMs();
        aamServices.deleteFromCacheInternalAAMs();
        aamServices.deleteFromCacheComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME, sspManagementRequest.getSspInstanceId());
        return new SspManagementResponse(sspManagementRequest.getSspInstanceId(), ManagementStatus.OK);
    }


    public SspManagementResponse authManage(SspManagementRequest request) throws
            SecurityException {
        // check if we received required credentials
        if (request.getAamOwnerCredentials() == null || request.getSspOwnerCredentials() == null)
            throw new InvalidArgumentsException(InvalidArgumentsException.MISSING_CREDENTIALS);
        // check if this operation is authorized
        if (!request.getAamOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAamOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new WrongCredentialsException();
        return this.manage(request);
    }
}
