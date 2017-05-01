package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.*;
import eu.h2020.symbiote.security.commons.json.ApplicationRegistrationRequest;
import eu.h2020.symbiote.security.commons.json.ApplicationRegistrationResponse;
import eu.h2020.symbiote.security.commons.json.Credentials;
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
 * Spring service used to register applications on AAM.
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
    private String AAMOwnerPassword; //FIXME this should be somehow encoded
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

    public ApplicationRegistrationResponse register(ApplicationRegistrationRequest applicationRegistrationRequest)
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
            IOException {

        Credentials user = applicationRegistrationRequest.getApplicationCredentials();

        // validate request
        if (deploymentType != IssuingAuthorityType.PLATFORM &&
                (applicationRegistrationRequest.getRecoveryMail()
                        .isEmpty() || applicationRegistrationRequest.getFederatedId().isEmpty()))
            throw new MissingArgumentsException("Missing recovery e-mail or federated identity");
        if (user.getUsername().isEmpty() || user.getPassword().isEmpty()) {
            throw new MissingArgumentsException("Missing username or password");
        } else if (userRepository.exists(user.getUsername())) {
            throw new ExistingUserException();
        }

        // Generate key pair for the new application
        KeyPair applicationKeyPair = registrationManager.createKeyPair();

        // Generate certificate for the application
        X509Certificate applicationCertificate = registrationManager.createECCert(user.getUsername(),
                applicationKeyPair.getPublic());
        Certificate certificate = new Certificate(registrationManager.convertX509ToPEM
                (applicationCertificate));

        // Register the user (Application type)
        User application = new User();
        application.setRole(User.Role.APPLICATION);
        application.setUsername(user.getUsername());
        application.setPasswordEncrypted(passwordEncoder.encode(user.getPassword()));
        application.setRecoveryMail(applicationRegistrationRequest.getRecoveryMail());
        application.setCertificate(certificate);
        userRepository.save(application);

        // Save Certificate to DB
        // TODO do we need to store it there if it is already stored with the application?
        certificateRepository.save(certificate);

        String pemApplicationCertificate = registrationManager.convertX509ToPEM(applicationCertificate);
        String pemApplicationPrivateKey = registrationManager.convertPrivateKeyToPEM(applicationKeyPair
                .getPrivate());

        return new ApplicationRegistrationResponse(pemApplicationCertificate, pemApplicationPrivateKey);
    }

    public ApplicationRegistrationResponse authRegister(ApplicationRegistrationRequest request) throws
            ExistingUserException,
            MissingArgumentsException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, UnrecoverableKeyException, CertificateException, OperatorCreationException,
            KeyStoreException, IOException, UnauthorizedRegistrationException, WrongCredentialsException {

        // check if we received required credentials
        if (request.getAAMOwnerCredentials() == null || request.getApplicationCredentials() == null)
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

    public void authUnregister(ApplicationRegistrationRequest request) throws MissingArgumentsException,
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
}
