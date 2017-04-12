package eu.h2020.symbiote.services;

import eu.h2020.symbiote.commons.Application;
import eu.h2020.symbiote.commons.RegistrationManager;
import eu.h2020.symbiote.commons.exceptions.*;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.commons.json.RegistrationRequest;
import eu.h2020.symbiote.commons.json.RegistrationResponse;
import eu.h2020.symbiote.model.CertificateModel;
import eu.h2020.symbiote.repositories.ApplicationRepository;
import eu.h2020.symbiote.repositories.CertificateRepository;
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
 * Spring service used to register applications on CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Service
public class ApplicationRegistrationService {
    private final ApplicationRepository applicationRepository;
    private final CertificateRepository certificateRepository;
    private final RegistrationManager registrationManager;
    private final PasswordEncoder passwordEncoder;

    @Value("${platformowner.username}")
    private String platformOwnerUsername;
    @Value("${platformowner.password}")
    private String platformOwnerPassword;

    @Autowired
    public ApplicationRegistrationService(ApplicationRepository applicationRepository, CertificateRepository
            certificateRepository, RegistrationManager registrationManager, PasswordEncoder passwordEncoder) {
        this.applicationRepository = applicationRepository;
        this.certificateRepository = certificateRepository;
        this.registrationManager = registrationManager;
        this.passwordEncoder = passwordEncoder;
    }

    public RegistrationResponse register(LoginRequest user) throws MissingArgumentsException,
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

        if (user.getUsername() != null || user.getPassword() != null) {
            if (applicationRepository.exists(user.getUsername())) {
                throw new ExistingApplicationException();
            } else {

                // Generate key pair for the new application
                KeyPair applicationKeyPair = registrationManager.createKeyPair();

                // Generate certificate for the application
                X509Certificate applicationCertificate = registrationManager.createECCert(user.getUsername(),
                        applicationKeyPair.getPublic());

                // Register the user (Application)
                Application application = new Application();
                application.setPasswordEncrypted(passwordEncoder.encode(user.getPassword()));
                applicationRepository.save(application);

                // Save Certificate to DB
                certificateRepository.save(new CertificateModel(applicationCertificate));

                String pemApplicationCertificate = registrationManager.convertX509ToPEM(applicationCertificate);
                String pemApplicationPrivateKey = registrationManager.convertPrivateKeyToPEM(applicationKeyPair.getPrivate());

                return new RegistrationResponse(pemApplicationCertificate,pemApplicationPrivateKey);

            }
        } else {
            throw new MissingArgumentsException();
        }

    }

    public RegistrationResponse authRegister(RegistrationRequest request) throws ExistingApplicationException, MissingArgumentsException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, CertificateException, OperatorCreationException, KeyStoreException, IOException, UnauthorizedRegistrationException, WrongCredentialsException {

        if(request.getPlatformOwner() != null || request.getApplication() != null) {
            if (request.getPlatformOwner().getUsername().equals(platformOwnerUsername) && request.getPlatformOwner().getPassword().equals(platformOwnerPassword)) {
                return this.register(request.getApplication());
            } else{
                throw new UnauthorizedRegistrationException();
            }
        } else {
            throw new MissingArgumentsException();
        }
    }

    public void unregister(LoginRequest user) throws NotExistingApplicationException, MissingArgumentsException {

        if (user.getUsername() != null || user.getPassword() != null) {
            if (applicationRepository.exists(user.getUsername())) {
                applicationRepository.delete(user.getUsername());
                return;
            } else {
                throw new NotExistingApplicationException();
            }
        } else {
            throw new MissingArgumentsException();
        }
    }

    public void authUnregister(RegistrationRequest request) throws MissingArgumentsException, NotExistingApplicationException, UnauthorizedUnregistrationException {

        if(request.getPlatformOwner() != null || request.getApplication() != null) {
            if (request.getPlatformOwner().getUsername().equals(platformOwnerUsername) && request.getPlatformOwner().getPassword().equals(platformOwnerPassword)) {
                this.unregister(request.getApplication());
            } else {
                throw new UnauthorizedUnregistrationException();
            }
        } else {
            throw new MissingArgumentsException();
        }
    }
}
