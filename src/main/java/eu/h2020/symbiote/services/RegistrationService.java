package eu.h2020.symbiote.services;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import eu.h2020.symbiote.commons.exceptions.*;
import eu.h2020.symbiote.commons.json.RegistrationRequest;
import eu.h2020.symbiote.commons.json.RegistrationResponse;
import eu.h2020.symbiote.model.CertificateModel;
import eu.h2020.symbiote.repositories.CertificateRepository;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;


import eu.h2020.symbiote.commons.RegistrationManager;
import eu.h2020.symbiote.commons.json.LoginRequest;
import eu.h2020.symbiote.model.UserModel;
import eu.h2020.symbiote.repositories.UserRepository;


/**
 * Spring service used to register applications on CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Service
public class RegistrationService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired

    private RegistrationManager registrationManager;
    @Value("${platformowner.username}")
    private String platformOwnerUsername;
    @Value("${platformowner.password}")
    private String platformOwnerPassword;

    public RegistrationResponse register(LoginRequest user) throws ExistingApplicationException, MissingArgumentsException,InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, CertificateException, OperatorCreationException, KeyStoreException, IOException {

        if(user.getUsername() != null || user.getPassword() != null) {
            if(userRepository.exists(user.getUsername())){
                throw new ExistingApplicationException();
                }
                else{

                // Generate key pair for the new application
                KeyPair applicationKeyPair = registrationManager.createKeyPair();

                // Generate certificate for the application
                X509Certificate applicationCertificate = registrationManager.createECCert(user.getUsername(), applicationKeyPair.getPublic());

                // Register the application (User)
                userRepository.save(new UserModel(user.getUsername(),user.getPassword()));

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

    public RegistrationResponse authRegister(RegistrationRequest request) throws ExistingApplicationException, MissingArgumentsException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, CertificateException, OperatorCreationException, KeyStoreException, IOException, UnauthorizedRegistrationException {

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

        if(user.getUsername() != null || user.getPassword() != null) {
            if(userRepository.exists(user.getUsername())){
                userRepository.delete(user.getUsername());
            }
            else{
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
