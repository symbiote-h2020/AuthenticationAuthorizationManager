package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * TODO @Maks finish it! and comment properly
 *
 * @author Maks Marcinowski (PSNC)
 */

@Service
public class GetClientCertificateService {
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
    private static final Log log = LogFactory.getLog(GetClientCertificateService.class);


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

    private void platformRequestCheck(CertificateRequest certificateRequest) throws
            PlatformManagementException {
        PKCS10CertificationRequest req = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());
        if (userRepository.findOne(certificateRequest.getUsername()).getRole() != UserRole.PLATFORM_OWNER) {
            throw new PlatformManagementException("User is not a Platform Owner", HttpStatus.UNAUTHORIZED);
        }
        if (!platformRepository.exists(req.getSubject().toString().split("CN=")[1])) {
            throw new PlatformManagementException("Platform doesn't exist", HttpStatus.UNAUTHORIZED);
        }
    }

    private User requestValidationCheck(CertificateRequest certificateRequest) throws
            ValidationException,
            WrongCredentialsException,
            NotExistingUserException {

        User user = userRepository.findOne(certificateRequest.getUsername());
        if (user == null)
            throw new NotExistingUserException();

        if (!passwordEncoder.matches(certificateRequest.getPassword(), user.getPasswordEncrypted()))
            throw new WrongCredentialsException();

        if (revokedKeysRepository.exists(certificateRequest.getUsername()))
            throw new ValidationException("Key revoked");

        return user;
    }

    private X509Certificate certFromCSRCreation(CertificateRequest certificateRequest) throws
            InvalidArgumentsException, UserManagementException, PlatformManagementException {
        X509Certificate certFromCSR;
        X509Certificate caCert;

        PKCS10CertificationRequest req = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());

        try {
            caCert = certificationAuthorityHelper.getAAMCertificate();
        } catch (NoSuchAlgorithmException | CertificateException | NoSuchProviderException
                | KeyStoreException | IOException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }

        if (!req.getSubject().toString().split("CN=")[1].contains(CryptoHelper.illegalSign)) {
            platformRequestCheck(certificateRequest);

            try {
                certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, true);
            } catch (CertificateException e) {
                log.error(e);
                throw new PlatformManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }
        //else if(req.getSubject().toString().split("CN=")[1].split("illegalSign")[2]==null){

        //}
        else {
            if (!req.getSubject().toString().split("CN=")[1].split("@")[2].equals
                    (caCert.getSubjectDN().getName().split("CN=")[1]))
                throw new InvalidArgumentsException("Subject name doesn't match");

            try {
                certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
            } catch (CertificateException e) {
                log.error(e);
                throw new UserManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }
        return certFromCSR;
    }

    public String getCertificate(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException {


        if (certificateRequest.getUsername().contains(CryptoHelper.illegalSign) || certificateRequest.getClientId().contains(CryptoHelper.illegalSign))
            throw new InvalidArgumentsException();

        User user = requestValidationCheck(certificateRequest);

        X509Certificate certFromCSR = certFromCSRCreation(certificateRequest);

        String pem;
        try {
            pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        } catch (IOException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }

        Certificate userCert = user.getClientCertificates().get(certificateRequest.getClientId());
        if (userCert != null) {
            X509Certificate x509Certificate;
            try {
                x509Certificate = userCert.getX509();
            } catch (CertificateException e) {
                log.error(e);
                throw new SecurityException(e.getMessage(), e.getCause());
            }
            if (x509Certificate.getPublicKey().equals(certFromCSR.getPublicKey())) {
                Certificate cert = new Certificate(pem);
                user.getClientCertificates().clear();
                user.getClientCertificates().replace(certificateRequest.getClientId(), cert);
            } else {
                try {
                    revocationHelper.revoke(new Credentials(user.getUsername(), user.getPasswordEncrypted()), userCert);
                } catch (CertificateException e) {
                    log.error(e);
                    throw new SecurityException(e.getMessage(), e.getCause());
                }
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