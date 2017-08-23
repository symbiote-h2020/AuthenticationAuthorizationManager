package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
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

import static eu.h2020.symbiote.security.commons.SecurityConstants.AAM_CORE_AAM_INSTANCE_ID;
import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

/**
 * Spring service used to provide client certificates issuing
 *
 * @author Maksymilian Marcinowski (PSNC)
 */

@Service
public class GetClientCertificateService {
    private static final Log log = LogFactory.getLog(GetClientCertificateService.class);
    private final UserRepository userRepository;
    private final PlatformRepository platformRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final ComponentCertificatesRepository componentCertificatesRepository;
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
                                       ComponentCertificatesRepository componentCertificatesRepository, CertificationAuthorityHelper certificationAuthorityHelper,
                                       PasswordEncoder passwordEncoder,
                                       RevocationHelper revocationHelper) {
        this.userRepository = userRepository;
        this.platformRepository = platformRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.componentCertificatesRepository = componentCertificatesRepository;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.passwordEncoder = passwordEncoder;
        this.revocationHelper = revocationHelper;
    }

    public String getCertificate(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException {


        User user = requestValidationCheck(certificateRequest);
        PKCS10CertificationRequest req = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());

        X509Certificate certFromCSR = certFromCSRCreation(certificateRequest, req);

        String pem;
        try {
            pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        } catch (IOException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }
        // symbiote components
        if (req.getSubject().toString().matches("(CN=)(\\w+)(@)(\\w+)")) {
            platformComponentCertStorage(req, certificateRequest, pem, certFromCSR);
        }
        //platform
        else if (!req.getSubject().toString().split("CN=")[1].contains(illegalSign)) {
            platformCertStorage(req, certificateRequest, pem, certFromCSR);
        }

        // user / platform owner
        else {
            userCertStorage(user, certificateRequest, certFromCSR, pem);
        }

        return pem;
    }

    private void platformComponentCertStorage(PKCS10CertificationRequest req, CertificateRequest certificateRequest,
                                              String pem, X509Certificate certFromCSR) throws
            NotExistingUserException,
            WrongCredentialsException {

        String componentId = req.getSubject().toString().split("CN=")[1].split("@")[0];
        String platformId = req.getSubject().toString().split("CN=")[1].split("@")[1];

        if (platformId.equals(AAM_CORE_AAM_INSTANCE_ID)) {
            // core components
            if (certificateRequest.getUsername().equals(AAMOwnerUsername) && certificateRequest.getPassword().equals(AAMOwnerPassword)) {
                // TODO replace/revoke if exists!
                // uncomment when working if (!componentCertificatesRepository.exists(componentId))
                componentCertificatesRepository.save(new ComponentCertificate(componentId, new Certificate(pem)));
            }
        } else {
            // platform component
            Platform platform = platformRepository.findOne(platformId);

            Certificate platformComponentCert = platform.getComponentCertificates().get(componentId);
            if (platformComponentCert != null) {
                X509Certificate x509Component;
                try {
                    x509Component = platformComponentCert.getX509();
                } catch (CertificateException e) {
                    log.error(e);
                    throw new SecurityException(e.getMessage(), e.getCause());
                }
                if (x509Component.getPublicKey().equals(certFromCSR.getPublicKey())) {
                    platform.getComponentCertificates().replace(componentId, new Certificate(pem));
                } else {
                    try {
                        revocationHelper.revokeCertificate(new Credentials(certificateRequest.getUsername(), certificateRequest.getPassword()), platformComponentCert, componentId + illegalSign + platformId);
                    } catch (CertificateException | IOException e) {
                        log.error(e);
                        throw new SecurityException(e.getMessage(), e.getCause());
                    }
                    platform.getComponentCertificates().put(componentId, new Certificate(pem));
                }
            } else {
                platform.getComponentCertificates().put(componentId, new Certificate(pem));
            }
            platformRepository.save(platform);
        }
    }

    private void platformCertStorage(PKCS10CertificationRequest req, CertificateRequest certificateRequest,
                                     String pem, X509Certificate certFromCSR) throws
            NotExistingUserException,
            WrongCredentialsException {

        String platformId = req.getSubject().toString().split("CN=")[1];
        Platform platform = platformRepository.findOne(platformId);

        Certificate platformCert = platform.getPlatformAAMCertificate();
        if (!platformCert.getCertificateString().isEmpty()) {
            X509Certificate x509Platform;
            try {
                x509Platform = platformCert.getX509();
            } catch (CertificateException e) {
                log.error(e);
                throw new SecurityException(e.getMessage(), e.getCause());
            }
            if (x509Platform.getPublicKey().equals(certFromCSR.getPublicKey())) {
                platform.setPlatformAAMCertificate(new Certificate(pem));
            } else {
                try {
                    revocationHelper.revokeCertificate(new Credentials(certificateRequest.getUsername(), certificateRequest.getPassword()), platformCert, platformId);
                } catch (CertificateException | IOException e) {
                    log.error(e);
                    throw new SecurityException(e.getMessage(), e.getCause());
                }
                platform.setPlatformAAMCertificate(new Certificate(pem));
            }
        } else {
            platform.setPlatformAAMCertificate(new Certificate(pem));
        }
        platformRepository.save(platform);
    }

    private void userCertStorage(User user, CertificateRequest certificateRequest, X509Certificate certFromCSR,
                                 String pem) throws
            NotExistingUserException,
            WrongCredentialsException {

        Certificate userCert = user.getClientCertificates().get(certificateRequest.getClientId());
        if (userCert != null) {
            X509Certificate x509User;
            try {
                x509User = userCert.getX509();
            } catch (CertificateException e) {
                log.error(e);
                throw new SecurityException(e.getMessage(), e.getCause());
            }
            if (x509User.getPublicKey().equals(certFromCSR.getPublicKey())) {
                Certificate cert = new Certificate(pem);
                user.getClientCertificates().replace(certificateRequest.getClientId(), cert);
            } else {
                try {
                    revocationHelper.revokeCertificate(new Credentials(certificateRequest.getUsername(), certificateRequest.getPassword()), userCert, user.getUsername() + illegalSign + certificateRequest.getClientId());
                } catch (CertificateException | IOException e) {
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
        userRepository.save(user);
    }


    private X509Certificate certFromCSRCreation(CertificateRequest certificateRequest, PKCS10CertificationRequest req) throws
            InvalidArgumentsException, UserManagementException, PlatformManagementException {
        X509Certificate certFromCSR;

        //platform
        if (!req.getSubject().toString().split("CN=")[1].contains(illegalSign)) {
            certFromCSR = platformCertFromCSRCreation(certificateRequest, req);
        }
        //platform component
        else if (req.getSubject().toString().matches("(CN=)(\\w+)(@)(\\w+)")) {
            certFromCSR = platformComponentCertFromCSRCreation(certificateRequest, req);
        }
        //user
        else {
            certFromCSR = userCertfromCSRCreation(req);
        }
        return certFromCSR;
    }

    private X509Certificate userCertfromCSRCreation(PKCS10CertificationRequest req)
            throws InvalidArgumentsException, UserManagementException {
        X509Certificate certFromCSR;
        X509Certificate caCert;

        try {
            caCert = certificationAuthorityHelper.getAAMCertificate();
        } catch (NoSuchAlgorithmException | CertificateException | NoSuchProviderException
                | KeyStoreException | IOException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }

        if (!req.getSubject().toString().split("CN=")[1].split("@")[2].equals
                (caCert.getSubjectDN().getName().split("CN=")[1]))
            throw new InvalidArgumentsException("Subject name doesn't match");

        try {
            certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        } catch (CertificateException e) {
            log.error(e);
            throw new UserManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return certFromCSR;
    }


    private X509Certificate platformCertFromCSRCreation(CertificateRequest certificateRequest, PKCS10CertificationRequest req)
            throws PlatformManagementException {
        X509Certificate certFromCSR;
        platformRequestCheck(certificateRequest);
        try {
            certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, true);
        } catch (CertificateException e) {
            log.error(e);
            throw new PlatformManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return certFromCSR;
    }

    private X509Certificate platformComponentCertFromCSRCreation(CertificateRequest certificateRequest, PKCS10CertificationRequest req)
            throws PlatformManagementException {
        X509Certificate certFromCSR;
        platformComponentRequestCheck(certificateRequest);
        try {
            certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        } catch (CertificateException e) {
            log.error(e);
            throw new PlatformManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return certFromCSR;
    }

    private User requestValidationCheck(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException {

        User user = userRepository.findOne(certificateRequest.getUsername());

        if (user == null)
            throw new NotExistingUserException();

        if (!passwordEncoder.matches(certificateRequest.getPassword(), user.getPasswordEncrypted()))
            throw new WrongCredentialsException();
        //TODO check if key sent in certificate is revoked
        return user;
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

    private void platformComponentRequestCheck(CertificateRequest certificateRequest) throws
            PlatformManagementException {
        PKCS10CertificationRequest req = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());
        if (userRepository.findOne(certificateRequest.getUsername()).getRole() != UserRole.PLATFORM_OWNER) {
            throw new PlatformManagementException("User is not a Platform Owner", HttpStatus.UNAUTHORIZED);
        }
        if (!platformRepository.exists(req.getSubject().toString().split("CN=")[1].split(illegalSign)[1])) {
            throw new PlatformManagementException("Platform doesn't exist", HttpStatus.UNAUTHORIZED);
        }
    }
}