package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.commons.TokenManager;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.rest.CertificateRequest;
import eu.h2020.symbiote.security.rest.CoreServicesController;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

/**
 * @author Maks Marcinowski (PSNC)
 */

@Service
public class CertificateService {
    private static Log log = LogFactory.getLog(UserRegistrationService.class);
    private final UserRepository userRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final RegistrationManager registrationManager;
    private final PasswordEncoder passwordEncoder;
    private final CoreServicesController coreServicesController;
    private final TokenManager tokenManager;
    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;
    public static final String illegalSign = "@";
    private static final long keyValidityPeriod = 1000;

    @Autowired
    public CertificateService(UserRepository userRepository, RevokedKeysRepository revokedKeysRepository, RegistrationManager registrationManager,
                                   PasswordEncoder passwordEncoder, CoreServicesController coreServicesController, TokenManager tokenManager) {
        this.userRepository = userRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.registrationManager = registrationManager;
        this.passwordEncoder = passwordEncoder;
        this.coreServicesController = coreServicesController;
        this.tokenManager = tokenManager;
    }

    public String getCertificate (CertificateRequest certificateRequest) throws WrongCredentialsException, IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, UnrecoverableKeyException, OperatorCreationException, NotExistingUserException, InvalidKeyException {
        if(certificateRequest.getUsername().contains(illegalSign) || certificateRequest.getPassword().contains(illegalSign))
               throw new IllegalArgumentException("Credentials contain illegal sign");

        User user = userRepository.findOne(certificateRequest.getUsername());
        if(user==null)
            throw new NotExistingUserException();

        if (!passwordEncoder.matches(certificateRequest.getPassword(), user.getPasswordEncrypted()))
            throw new WrongCredentialsException();

        if(revokedKeysRepository.exists(certificateRequest.getUsername()))
            throw new InvalidKeyException();

        X509Certificate clientCert = registrationManager.convertPEMToX509(certificateRequest.getClientCSR());
        if(!user.getCertificate().getX509().equals(clientCert))
            throw new CertificateException();

        ResponseEntity<String> response = coreServicesController.getCACert();
        X509Certificate caCert = registrationManager.convertPEMToX509(response.getBody());
        X500Name issuer = new X500Name( caCert.getSubjectX500Principal().getName() );
        PrivateKey privKey = registrationManager.getAAMPrivateKey();

        X500Principal principal = user.getCertificate().getX509().getSubjectX500Principal();
        X500Name x500name = new X500Name(principal.getName());

        X500Name commonName = new X500Name(certificateRequest.getUsername() + illegalSign + clientCert.getSubjectDN().getName()+ illegalSign + certificateRequest.getClientId());

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis()+keyValidityPeriod),
                //new Date(System.currentTimeMillis() + 1L * 365L * 24L * 60L * 60L * 1000L),
                commonName,
                clientCert.getPublicKey())
                .addExtension(
                        new ASN1ObjectIdentifier("2.5.29.19"),
                        false,
                        new BasicConstraints(false));
        ContentSigner sigGen = new JcaContentSignerBuilder(caCert.getSigAlgName()).setProvider(PROVIDER_NAME).build(privKey);
        X509Certificate cert509 = new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certGen.build(sigGen));

        String pem = registrationManager.convertX509ToPEM(cert509);

        if(x500name.equals(certificateRequest.getClientId()))
        {
            if(user.getCertificate().getX509().getPublicKey().equals(clientCert.getPublicKey())) {
                eu.h2020.symbiote.security.certificate.Certificate cert = new eu.h2020.symbiote.security.certificate.Certificate();
                cert.setCertificateString(pem);
                user.setCertificate(cert);
            }
            else{
                //Set<String> keys = new HashSet<>();
                //keys.add(Base64.getEncoder().encodeToString(
                //        userRepository.findOne(certificateRequest.getUsername()).getCertificate().getX509().getPublicKey().getEncoded()));
                //revokedKeysRepository.save(new SubjectsRevokedKeys(issuer.toString(), keys));
                tokenManager.revoke(new Credentials(user.getUsername(),user.getPasswordEncrypted()),user.getCertificate());
                eu.h2020.symbiote.security.certificate.Certificate cert = new eu.h2020.symbiote.security.certificate.Certificate();
                cert.setCertificateString(pem);
                user.setCertificate(cert);
            }
        }
        else {
            eu.h2020.symbiote.security.certificate.Certificate cert = new eu.h2020.symbiote.security.certificate.Certificate();
            cert.setCertificateString(pem);
        }

        return pem;
    }

    /*public Certificate getCertificate(String username, String password, String clientId, PKCS10CertificationRequest clientCSR)
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
    }*/
}
