package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.commons.SubjectsRevokedKeys;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.SecurityException;
import eu.h2020.symbiote.security.exceptions.custom.*;
import eu.h2020.symbiote.security.payloads.UserDetails;
import eu.h2020.symbiote.security.payloads.UserRegistrationRequest;
import eu.h2020.symbiote.security.payloads.UserRegistrationResponse;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.rest.CoreServicesController;
import eu.h2020.symbiote.security.session.AAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

/**
 * Spring service used to register users in the AAM repository.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class UserRegistrationService {
    private static Log log = LogFactory.getLog(UserRegistrationService.class);
    private final UserRepository userRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final RegistrationManager registrationManager;
    private final PasswordEncoder passwordEncoder;
    private final CoreServicesController coreServicesController;
    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;
    private IssuingAuthorityType deploymentType;
    public static final String AT = "@";

    @Autowired
    public UserRegistrationService(UserRepository userRepository, RevokedKeysRepository revokedKeysRepository, RegistrationManager registrationManager,
                                   PasswordEncoder passwordEncoder, CoreServicesController coreServicesController) {
        this.userRepository = userRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.registrationManager = registrationManager;
        this.passwordEncoder = passwordEncoder;
        this.deploymentType = registrationManager.getDeploymentType();
        this.coreServicesController = coreServicesController;
    }

    public UserRegistrationResponse register(UserRegistrationRequest userRegistrationRequest)
            throws SecurityException {

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

        // verify proper user role
        if (user.getRole() == UserRole.NULL)
            throw new UserRegistrationException();


        Certificate certificate;
        String applicationPEMPrivateKey;

        try {
            // Generate key pair for the new user
            KeyPair applicationKeyPair = registrationManager.createKeyPair();

            // Generate PEM certificate for the user
            certificate = new Certificate(registrationManager.convertX509ToPEM
                    (registrationManager.createECCert(user.getCredentials().getUsername(),
                            applicationKeyPair.getPublic())));

            applicationPEMPrivateKey = registrationManager.convertPrivateKeyToPEM(applicationKeyPair
                    .getPrivate());

        } catch (NoSuchProviderException | NoSuchAlgorithmException | IOException |
                InvalidAlgorithmParameterException | UnrecoverableKeyException | OperatorCreationException |
                KeyStoreException | CertificateException e) {
            log.error(e);
            throw new UserRegistrationException(e);
        }

        // Register the user
        User application = new User();
        application.setRole(user.getRole());
        application.setUsername(user.getCredentials().getUsername());
        application.setPasswordEncrypted(passwordEncoder.encode(user.getCredentials().getPassword()));
        application.setRecoveryMail(user.getRecoveryMail());
        application.setCertificate(certificate);
        userRepository.save(application);

        return new UserRegistrationResponse(certificate, applicationPEMPrivateKey);
    }

    public UserRegistrationResponse authRegister(UserRegistrationRequest request) throws
            SecurityException {

        // check if we received required credentials
        if (request.getAAMOwnerCredentials() == null || request.getUserDetails().getCredentials() == null)
            throw new MissingArgumentsException();
        // check if this operation is authorized
        if (!request.getAAMOwnerCredentials().getUsername().equals(AAMOwnerUsername)
                || !request.getAAMOwnerCredentials().getPassword().equals(AAMOwnerPassword))
            throw new UnauthorizedRegistrationException();
        return this.register(request);
    }

    public void unregister(String username) throws SecurityException {
        // validate request
        if (username.isEmpty())
            throw new MissingArgumentsException();
        // try-find user
        if (!userRepository.exists(username))
            throw new NotExistingUserException();

        // add user certificated to revoked repository
        Set<String> keys = new HashSet<>();
        try {
            keys.add(Base64.getEncoder().encodeToString(
                    userRepository.findOne(username).getCertificate().getX509().getPublicKey().getEncoded()));
            revokedKeysRepository.save(new SubjectsRevokedKeys(username, keys));
        } catch (CertificateException e) {
            log.error(e);
            throw new UserRegistrationException(e);
        }
        // do it
        userRepository.delete(username);
    }

    public void authUnregister(UserRegistrationRequest request) throws SecurityException {

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

    public Certificate getCertificate(String username, String password, String clientId, PKCS10CertificationRequest clientCSR)
            throws SecurityHandlerException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, NoSuchProviderException, InvalidKeyException, IOException, WrongCredentialsException, NotExistingUserException {

        User user = userRepository.findOne(username);
        if(user==null)
            throw new NotExistingUserException();

        if (!passwordEncoder.matches(password, user.getPasswordEncrypted()))
            throw new WrongCredentialsException();

        if(revokedKeysRepository.exists(username))
            throw new InvalidKeyException();

        X500Principal principal = user.getCertificate().getX509().getSubjectX500Principal();
        X500Name x500name = new X500Name(principal.getName());

        JcaPKCS10CertificationRequest jcaCertRequest = new JcaPKCS10CertificationRequest(clientCSR.getEncoded()).setProvider("BC");
        if(x500name.equals(clientId))
        {
            if(user.getCertificate().getX509().getPublicKey().equals(jcaCertRequest.getPublicKey())) {
                Certificate cert = new Certificate();
                cert.setCertificateString(registrationManager.convertX509ToPEM(registrationManager.generateCertificateFromCSR(clientCSR)));
                user.setCertificate(cert);
                return cert;
            }
            else{
                Set<String> keys = new HashSet<>();
                keys.add(Base64.getEncoder().encodeToString(
                        userRepository.findOne(username).getCertificate().getX509().getPublicKey().getEncoded()));
                revokedKeysRepository.save(new SubjectsRevokedKeys(username, keys));
                Certificate cert = new Certificate();
                cert.setCertificateString(registrationManager.convertX509ToPEM(registrationManager.generateCertificateFromCSR(clientCSR)));
                user.setCertificate(cert);
                return cert;
            }
        }
        else{
            Certificate cert = new Certificate();
            cert.setCertificateString(registrationManager.convertX509ToPEM(registrationManager.generateCertificateFromCSR(clientCSR)));
            return cert;
        }
    }

    @RequestMapping(value = "/getCertificate", method = RequestMethod.POST)
    ResponseEntity<String> IGetCertififcateInterface (@RequestBody AAM homeAAM, String username, String password, String clientId, String clientCSR) throws WrongCredentialsException, IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, UnrecoverableKeyException, OperatorCreationException {
        if(username.contains(AT)||clientId.contains(AT)||homeAAM.getAamInstanceId().contains(AT))
            throw new IllegalArgumentException("Credentials contain illegal sign");
        //User user = new UserRegistrationRequest(new Credentials(AAMOwnerUsername, AAMOwnerPassword), new UserDetails(new Credentials(username, password), clientId, "", UserRole.APPLICATION))
        ResponseEntity<String> response = coreServicesController.getCACert();
        X509Certificate caCert = registrationManager.convertPEMToX509(response.getBody());
        X500Name issuer = new X500Name( caCert.getSubjectX500Principal().getName() );
        PrivateKey privKey = registrationManager.getAAMPrivateKey();
        X509Certificate clientCert = registrationManager.convertPEMToX509(clientCSR);

        ContentSigner sigGen = new JcaContentSignerBuilder(caCert.getSigAlgName()).setProvider(PROVIDER_NAME).build
                (privKey);
        X500Name commonName = new X500Name(username + AT + clientCert.getSubjectDN().getName()+ AT + clientId);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + 1L * 365L * 24L * 60L * 60L * 1000L),
                commonName,
                clientCert.getPublicKey())
                .addExtension(
                        new ASN1ObjectIdentifier("2.5.29.19"),
                        false,
                        new BasicConstraints(false));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certGen
                .build(sigGen));

        String pem = registrationManager.convertX509ToPEM(cert);
        return new ResponseEntity<String>(pem, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
