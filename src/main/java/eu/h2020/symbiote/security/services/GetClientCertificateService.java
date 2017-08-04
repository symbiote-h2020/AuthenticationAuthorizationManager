package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * TODO @Maks finish it! and comment properly
 *
 * @author Maks Marcinowski (PSNC)
 */

@Service
public class GetClientCertificateService {
    public static final String illegalSign = "@";
    private final UserRepository userRepository;
    private final PlatformRepository platformRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final PasswordEncoder passwordEncoder;
    private final RevocationHelper revocationHelper;
    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;

    @Autowired
    public GetClientCertificateService(UserRepository userRepository, PlatformRepository platformRepository,
                                       RevokedKeysRepository revokedKeysRepository,
                                       CertificationAuthorityHelper certificationAuthorityHelper,
                                       PasswordEncoder passwordEncoder,
                                       RevocationHelper revocationHelper) {
        this.userRepository = userRepository;
        this.platformRepository = platformRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.passwordEncoder = passwordEncoder;
        this.revocationHelper = revocationHelper;
    }

    public String getCertificate(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            IOException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            UnrecoverableKeyException,
            OperatorCreationException,
            NotExistingUserException,
            InvalidKeyException, InvalidArgumentsException, CertificateException {

        X509Certificate certFromCSR;

        if (certificateRequest.getUsername().contains(illegalSign) || certificateRequest.getClientId().contains(illegalSign))
            throw new IllegalArgumentException("Credentials contain illegal sign");

        User user = userRepository.findOne(certificateRequest.getUsername());
        if (user == null)
            throw new NotExistingUserException("User doesn't exists");

        if (!passwordEncoder.matches(certificateRequest.getPassword(), user.getPasswordEncrypted()))
            throw new WrongCredentialsException("Wrong credentials");

        if (revokedKeysRepository.exists(certificateRequest.getClientId()))
            throw new InvalidKeyException("Key revoked");

        PKCS10CertificationRequest req = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());

        X509Certificate caCert = certificationAuthorityHelper.getAAMCertificate();

        if (!req.getSubject().toString().split("CN=")[1].contains(illegalSign)) {
            if (userRepository.findOne(certificateRequest.getUsername()).getRole() != UserRole.PLATFORM_OWNER) {
                throw new SecurityException("User is not a Platform Owner");
            }

            if (!platformRepository.exists(req.getSubject().toString().split("CN=")[1])) {
                throw new SecurityException("Platform doesn't exist");
            }
            certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, true);

        } else {
            if (!req.getSubject().toString().split("CN=")[1].split("@")[2].equals
                    (caCert.getSubjectDN().getName().split("CN=")[1]))
                throw new InvalidArgumentsException("Subject name doesn't match");
            certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        }

        String pem = CryptoHelper.convertX509ToPEM(certFromCSR);

        Certificate userCert = user.getClientCertificates().get(certificateRequest.getClientId());
        if (userCert != null) {
            if (userCert.getX509().getPublicKey().equals(certFromCSR.getPublicKey())) {
                Certificate cert = new Certificate(pem);
                user.getClientCertificates().clear();
                user.getClientCertificates().replace(certificateRequest.getClientId(), cert);
            } else {
                revocationHelper.revoke(new Credentials(user.getUsername(), user.getPasswordEncrypted()), userCert);
                Certificate cert = new Certificate(pem);
                user.getClientCertificates().put(certificateRequest.getClientId(), cert);
            }
        } else {
            Certificate cert = new Certificate(pem);
            user.getClientCertificates().put(certificateRequest.getClientId(), cert);
        }
        return pem;
    }
}