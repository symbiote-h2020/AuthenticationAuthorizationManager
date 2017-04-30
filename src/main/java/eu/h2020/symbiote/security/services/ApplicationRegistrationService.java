package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Application;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.*;
import eu.h2020.symbiote.security.commons.json.ApplicationRegistrationRequest;
import eu.h2020.symbiote.security.commons.json.ApplicationRegistrationResponse;
import eu.h2020.symbiote.security.commons.json.PlainCredentials;
import eu.h2020.symbiote.security.repositories.ApplicationRepository;
import eu.h2020.symbiote.security.repositories.CertificateRepository;
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
public class ApplicationRegistrationService {
    private final ApplicationRepository applicationRepository;
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
    public ApplicationRegistrationService(ApplicationRepository applicationRepository, CertificateRepository
            certificateRepository, RegistrationManager registrationManager, PasswordEncoder passwordEncoder) {
        this.applicationRepository = applicationRepository;
        this.certificateRepository = certificateRepository;
        this.registrationManager = registrationManager;
        this.passwordEncoder = passwordEncoder;
    }

    public ApplicationRegistrationResponse register(ApplicationRegistrationRequest applicationRegistrationRequest)
            throws MissingArgumentsException,
            ExistingApplicationException,
            WrongCredentialsException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            UnrecoverableKeyException,
            CertificateException,
            OperatorCreationException,
            KeyStoreException,
            IOException {

        PlainCredentials user = applicationRegistrationRequest.getApplicationCredentials();

        // validate request
        if (!user.getUsername().isEmpty() && !user.getPassword().isEmpty()) {
            if (deploymentType.equals(IssuingAuthorityType.CORE) && applicationRegistrationRequest.getRecoveryMail()
                    .isEmpty()) {
                throw new MissingArgumentsException("Missing recovery e-mail");
            } else if (applicationRepository.exists(user.getUsername())) {
                throw new ExistingApplicationException();
            }
        }

        // Generate key pair for the new application
        KeyPair applicationKeyPair = registrationManager.createKeyPair();

        // Generate certificate for the application
        X509Certificate applicationCertificate = registrationManager.createECCert(user.getUsername(),
                applicationKeyPair.getPublic());

        // Register the user (Application)
        Application application = new Application();
        application.setUsername(user.getUsername());
        application.setPasswordEncrypted(passwordEncoder.encode(user.getPassword()));
        application.setRecoveryMail(applicationRegistrationRequest.getRecoveryMail());
        applicationRepository.save(application);

        // Save Certificate to DB
        certificateRepository.save(new Certificate(registrationManager.convertX509ToPEM
                (applicationCertificate)));

        String pemApplicationCertificate = registrationManager.convertX509ToPEM(applicationCertificate);
        String pemApplicationPrivateKey = registrationManager.convertPrivateKeyToPEM(applicationKeyPair
                .getPrivate());

        return new ApplicationRegistrationResponse(pemApplicationCertificate, pemApplicationPrivateKey);
    }

    public ApplicationRegistrationResponse authRegister(ApplicationRegistrationRequest request) throws
            ExistingApplicationException,
            MissingArgumentsException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, UnrecoverableKeyException, CertificateException, OperatorCreationException,
            KeyStoreException, IOException, UnauthorizedRegistrationException, WrongCredentialsException {

        if (request.getAAMOwnerCredentials() != null || request.getApplicationCredentials() != null) {
            if (request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername) && request
                    .getAAMOwnerCredentials()
                    .getPassword().equals(AAMOwnerPassword)) {
                return this.register(request);
            } else {
                throw new UnauthorizedRegistrationException();
            }
        } else {
            throw new MissingArgumentsException();
        }
    }

    public void unregister(String username) throws NotExistingApplicationException, MissingArgumentsException {

        if (!username.isEmpty()) {
            if (applicationRepository.exists(username)) {
                applicationRepository.delete(username);
            } else {
                throw new NotExistingApplicationException();
            }
        } else {
            throw new MissingArgumentsException();
        }
    }

    public void authUnregister(ApplicationRegistrationRequest request) throws MissingArgumentsException,
            NotExistingApplicationException, UnauthorizedUnregistrationException {

        if (request.getAAMOwnerCredentials() != null || request.getApplicationCredentials() != null) {
            if (request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername) && request
                    .getAAMOwnerCredentials()
                    .getPassword().equals(AAMOwnerPassword)) {
                this.unregister(request.getApplicationCredentials().getUsername());
            } else {
                throw new UnauthorizedUnregistrationException();
            }
        } else {
            throw new MissingArgumentsException();
        }
    }
}
