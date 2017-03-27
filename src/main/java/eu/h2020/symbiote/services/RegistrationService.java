package eu.h2020.symbiote.services;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import eu.h2020.symbiote.commons.exceptions.NotExistingApplicationException;
import eu.h2020.symbiote.commons.json.RegistrationResponse;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


import eu.h2020.symbiote.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.commons.exceptions.WrongCredentialsException;
import eu.h2020.symbiote.commons.exceptions.ExistingApplicationException;
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
    private RegistrationManager registrationManager;

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

                return new RegistrationResponse(applicationCertificate,applicationKeyPair);

            }
        }
        throw new MissingArgumentsException();

    }

    public void unregister(LoginRequest user) throws NotExistingApplicationException, MissingArgumentsException {

        if(user.getUsername() != null || user.getPassword() != null) {
            if(userRepository.exists(user.getUsername())){
                userRepository.delete(user.getUsername());
                return;
            }
            else{
                throw new NotExistingApplicationException();
            }
        }
        throw new MissingArgumentsException();

    }
}
