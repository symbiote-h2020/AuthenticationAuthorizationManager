package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.*;
import eu.h2020.symbiote.security.commons.json.UserDetails;
import eu.h2020.symbiote.security.commons.json.UserRegistrationRequest;
import eu.h2020.symbiote.security.commons.json.UserRegistrationResponse;
import eu.h2020.symbiote.security.repositories.CertificateRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Spring service used to register users in the AAM repository.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class UserRegistrationService {
    private final UserRepository userRepository;
    private final CertificateRepository certificateRepository;
    private final RegistrationManager registrationManager;
    private final PasswordEncoder passwordEncoder;

    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;
    @Value("${aam.deployment.type}")
    private IssuingAuthorityType deploymentType;

    @Autowired
    public UserRegistrationService(UserRepository userRepository, CertificateRepository
            certificateRepository, RegistrationManager registrationManager, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.certificateRepository = certificateRepository;
        this.registrationManager = registrationManager;
        this.passwordEncoder = passwordEncoder;
    }

    public UserRegistrationResponse register(UserRegistrationRequest userRegistrationRequest)
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
            IOException, UserRegistrationException {

        UserDetails user = userRegistrationRequest.getUserDetails();

        // validate request
        if (deploymentType == IssuingAuthorityType.CORE &&
                (user.getRecoveryMail()
                        .isEmpty() || user.getFederatedId().isEmpty()))
            throw new MissingArgumentsException("Missing recovery e-mail or federated identity");
        if (user.getCredentials().getUsername().isEmpty() || user.getCredentials().getPassword().isEmpty()) {
            throw new MissingArgumentsException("Missing username or password");
        }
        // Platform AAM does not support registering platform owners
        if (deploymentType == IssuingAuthorityType.PLATFORM && user.getRole() != UserRole.APPLICATION)
            throw new UserRegistrationException();

        // check if user already in repository
        if (userRepository.exists(user.getCredentials().getUsername())) {
            throw new ExistingUserException();
        }

        // Generate key pair for the new user
        KeyPair applicationKeyPair = registrationManager.createKeyPair();

        // verify proper user role
        if (user.getRole() == UserRole.NULL)
            throw new UserRegistrationException();

        // Generate certificate for the user
        X509Certificate userX509Certificate = registrationManager.createECCert(user.getCredentials().getUsername(),
                applicationKeyPair.getPublic());

        Certificate certificate = new Certificate(registrationManager.convertX509ToPEM
                (userX509Certificate));

        // Register the user
        User application = new User();
        application.setRole(user.getRole());
        application.setUsername(user.getCredentials().getUsername());
        application.setPasswordEncrypted(passwordEncoder.encode(user.getCredentials().getPassword()));
        application.setRecoveryMail(user.getRecoveryMail());
        application.setCertificate(certificate);
        userRepository.save(application);

        // Save Certificate to DB
        // TODO do we need to store it there if it is already stored with the application?
        certificateRepository.save(certificate);

        String pemApplicationCertificate = registrationManager.convertX509ToPEM(userX509Certificate);
        String pemApplicationPrivateKey = registrationManager.convertPrivateKeyToPEM(applicationKeyPair
                .getPrivate());

        return new UserRegistrationResponse(pemApplicationCertificate, pemApplicationPrivateKey);
    }

    public UserRegistrationResponse authRegister(UserRegistrationRequest request) throws
            ExistingUserException,
            MissingArgumentsException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, UnrecoverableKeyException, CertificateException, OperatorCreationException,
            KeyStoreException, IOException, UnauthorizedRegistrationException, WrongCredentialsException, UserRegistrationException {

        // check if we received required credentials
        if (request.getAAMOwnerCredentials() == null || request.getUserDetails().getCredentials() == null)
            throw new MissingArgumentsException();
        // check if this operation is authorized
        if (!request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAAMOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new UnauthorizedRegistrationException();
        return this.register(request);
    }

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
        if (request.getAAMOwnerCredentials() == null || request.getUserDetails().getCredentials() == null)
            throw new MissingArgumentsException();
        // authorize
        if (!request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAAMOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new UnauthorizedUnregistrationException();
        // do it
        this.unregister(request.getUserDetails().getCredentials().getUsername());
    }
}
