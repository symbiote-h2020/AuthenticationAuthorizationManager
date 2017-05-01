package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.*;
import eu.h2020.symbiote.security.commons.json.*;
import eu.h2020.symbiote.security.repositories.CertificateRepository;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Spring service used to register platforms and their owners in the AAM repository.
 *
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class PlatformRegistrationService {
    private final UserRepository userRepository;
    private final UserRegistrationService userRegistrationService;
    private final PlatformRepository platformRepository;

    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword; //FIXME this should be somehow encoded
    @Value("${aam.deployment.type}")
    private IssuingAuthorityType deploymentType;

    @Autowired
    public PlatformRegistrationService(UserRepository userRepository, UserRegistrationService userRegistrationService, PlatformRepository platformRepository, CertificateRepository
            certificateRepository, RegistrationManager registrationManager, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.userRegistrationService = userRegistrationService;
        this.platformRepository = platformRepository;
    }

    public PlatformRegistrationResponse authRegister(PlatformRegistrationRequest request) throws
            ExistingUserException,
            MissingArgumentsException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, UnrecoverableKeyException, CertificateException, OperatorCreationException,
            KeyStoreException, IOException, UnauthorizedRegistrationException, WrongCredentialsException, ExistingPlatformException, UserRegistrationException {

        // check if we received required credentials
        if (request.getAAMOwnerCredentials() == null || request.getPlatformOwnerDetails().getCredentials() == null)
            throw new MissingArgumentsException();
        // check if this operation is authorized
        if (!request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAAMOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new UnauthorizedRegistrationException();
        return this.register(request);
    }

    public PlatformRegistrationResponse register(PlatformRegistrationRequest platformRegistrationRequest)
            throws MissingArgumentsException,
            ExistingUserException,
            WrongCredentialsException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            UnrecoverableKeyException,
            CertificateException,
            OperatorCreationException,
            KeyStoreException,
            IOException, ExistingPlatformException, UserRegistrationException, UnauthorizedRegistrationException {

        UserDetails platformOwnerDetails = platformRegistrationRequest.getPlatformOwnerDetails();

        // validate request
        if (deploymentType == IssuingAuthorityType.CORE &&
                (platformOwnerDetails.getRecoveryMail()
                        .isEmpty() || platformOwnerDetails.getFederatedId().isEmpty()))
            throw new MissingArgumentsException("Missing recovery e-mail or federated identity");
        if (platformOwnerDetails.getCredentials().getUsername().isEmpty() || platformOwnerDetails.getCredentials().getPassword().isEmpty()) {
            throw new MissingArgumentsException("Missing username or password");
        }

        // check if platform owner already in repository
        if (userRepository.exists(platformOwnerDetails.getCredentials().getUsername())) {
            throw new ExistingUserException();
        }

        // check if platform already in repository
        if (!platformRegistrationRequest.getPlatformId().isEmpty() && platformRepository.exists(platformRegistrationRequest.getPlatformId()))
            throw new ExistingPlatformException();

        // register platform owner in user repository
        UserRegistrationResponse userRegistrationResponse = userRegistrationService.authRegister(
                new UserRegistrationRequest(platformRegistrationRequest.getAAMOwnerCredentials(), platformOwnerDetails));

        // register platform in repository
        String platformId = platformRegistrationRequest.getPlatformId();
        // TODO implement

        return new PlatformRegistrationResponse(userRegistrationResponse.getPemCertificate(), userRegistrationResponse.getPemPrivateKey(), platformId);
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
        if (request.getAAMOwnerCredentials() == null || request.getApplicationCredentials() == null)
            throw new MissingArgumentsException();
        // authorize
        if (!request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAAMOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new UnauthorizedUnregistrationException();
        // do it
        this.unregister(request.getApplicationCredentials().getUsername());
    }
    */
}
