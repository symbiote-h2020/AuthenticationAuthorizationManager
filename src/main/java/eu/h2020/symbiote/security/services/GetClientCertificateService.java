package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.certificate.CertificateHelper;
import eu.h2020.symbiote.security.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.listeners.rest.AAMServices;
import eu.h2020.symbiote.security.payloads.CertificateRequest;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * TODO @Maks finish it!
 *
 * @author Maks Marcinowski (PSNC)
 */

@Service
public class GetClientCertificateService {
    public static final String illegalSign = "@";
    private static Log log = LogFactory.getLog(GetClientCertificateService.class);
    private final UserRepository userRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final PasswordEncoder passwordEncoder;
    private final AAMServices coreServicesController;
    private final RevocationHelper revocationHelper;
    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;

    @Autowired
    public GetClientCertificateService(UserRepository userRepository, RevokedKeysRepository revokedKeysRepository,
                                       CertificationAuthorityHelper certificationAuthorityHelper,
                                       PasswordEncoder passwordEncoder, AAMServices coreServicesController,
                                       ValidationHelper
                                               validationHelper, RevocationHelper revocationHelper) {
        this.userRepository = userRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.passwordEncoder = passwordEncoder;
        this.coreServicesController = coreServicesController;
        ValidationHelper validationHelper1 = validationHelper;
        this.revocationHelper = revocationHelper;
    }

    public String getCertificate(CertificateRequest certificateRequest) throws WrongCredentialsException, IOException,
            CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, UnrecoverableKeyException,
            OperatorCreationException, NotExistingUserException, InvalidKeyException {

        if (certificateRequest.getUsername().contains(illegalSign) || certificateRequest.getClientId().contains(illegalSign))
            throw new IllegalArgumentException("Credentials contain illegal sign");

        User user = userRepository.findOne(certificateRequest.getUsername());
        if (user == null)
            throw new NotExistingUserException("User doesn't exists");

        if (!passwordEncoder.matches(certificateRequest.getPassword(), user.getPasswordEncrypted()))
            throw new WrongCredentialsException("Wrong credentials");

        if (revokedKeysRepository.exists(certificateRequest.getUsername()))
            throw new InvalidKeyException("Key revoked");

        byte[] bytes = Base64.decodeBase64(certificateRequest.getClientCSR());
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(bytes);
        //System.out.println(req.getSubject().toString());
        if (!req.getSubject().toString().equals
                (certificationAuthorityHelper.getAAMCertificate().getSubjectDN().getName()))
            throw new CertificateException("Subject name doesn't match");

        ResponseEntity<String> response = coreServicesController.getComponentCertificate();
        X509Certificate caCert = CertificateHelper.convertPEMToX509(response.getBody());

        X500Principal principal = user.getCertificate().getX509().getSubjectX500Principal();
        log.debug("************");
        log.debug(principal.getName());
        log.debug("************");
        X500Name x500ClientId = new X500Name(principal.getName().split("CN=")[1].split("@")[1]);

        X509Certificate cert509 = certificationAuthorityHelper.generateCertificateFromCSR(req);

        String pem = CertificateHelper.convertX509ToPEM(cert509);

        if (x500ClientId.equals(certificateRequest.getClientId())) {
            if (user.getCertificate().getX509().getPublicKey().equals(cert509.getPublicKey())) {
                Certificate cert = new Certificate(pem);
                user.setCertificate(cert);
            } else {
                revocationHelper.revoke(new Credentials(user.getUsername(), user.getPasswordEncrypted()), user
                        .getCertificate());
                Certificate cert = new Certificate(pem);
                user.setCertificate(cert);
            }
        } else {
            Certificate cert = new Certificate(pem);
            user.setCertificate(cert);
        }

        return pem;
    }
}