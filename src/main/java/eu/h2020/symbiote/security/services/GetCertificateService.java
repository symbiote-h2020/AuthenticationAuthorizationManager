package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.RevokedKeysRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
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
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static eu.h2020.symbiote.security.commons.SecurityConstants.AAM_CORE_AAM_INSTANCE_ID;
import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

/**
 * Spring service used to provide client certificates issuing
 *
 * @author Maksymilian Marcinowski (PSNC)
 * @author Jakub Toczek (PSNC)
 */

@Service
public class GetCertificateService {
    private static final Log log = LogFactory.getLog(GetCertificateService.class);
    private final UserRepository userRepository;
    private final PlatformRepository platformRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final ComponentCertificatesRepository componentCertificatesRepository;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final PasswordEncoder passwordEncoder;
    private final RevocationService revocationService;
    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;


    @Autowired
    public GetCertificateService(UserRepository userRepository, PlatformRepository platformRepository,
                                 RevokedKeysRepository revokedKeysRepository,
                                 ComponentCertificatesRepository componentCertificatesRepository, CertificationAuthorityHelper certificationAuthorityHelper,
                                 PasswordEncoder passwordEncoder,
                                 RevocationService revocationService) {
        this.userRepository = userRepository;
        this.platformRepository = platformRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.componentCertificatesRepository = componentCertificatesRepository;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.passwordEncoder = passwordEncoder;
        this.revocationService = revocationService;
    }

    public String getCertificate(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            ValidationException {


        User user = requestValidationCheck(certificateRequest);
        PKCS10CertificationRequest request = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());

        X509Certificate certFromCSR = createCertificateFromCSR(certificateRequest, request);

        String pem;
        try {
            pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        } catch (IOException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }
        // symbiote components
        if (request.getSubject().toString().matches("(CN=)(\\w+)(@)(\\w+)")) {
            putComponentCertToRepository(request, certificateRequest, pem, certFromCSR);
        }
        //platform
        else if (!request.getSubject().toString().split("CN=")[1].contains(illegalSign)) {
            putPlatformCertToRepository(request, certificateRequest, pem, certFromCSR);
        }
        // user / platform owner
        else {
            putUserCertToRepository(user, certificateRequest, certFromCSR, pem);
        }
        return pem;
    }

    private void putComponentCertToRepository(PKCS10CertificationRequest req, CertificateRequest certificateRequest,
                                              String pem, X509Certificate certFromCSR) {

        String componentId = req.getSubject().toString().split("CN=")[1].split("@")[0];
        String platformId = req.getSubject().toString().split("CN=")[1].split("@")[1];

        if (platformId.equals(AAM_CORE_AAM_INSTANCE_ID)) {
            // core components
            if (certificateRequest.getUsername().equals(AAMOwnerUsername) && certificateRequest.getPassword().equals(AAMOwnerPassword)) {
                ComponentCertificate coreComponentCert = componentCertificatesRepository.findOne(componentId);
                if (coreComponentCert != null) {
                    X509Certificate x509CoreComponentCert;
                    try {
                        x509CoreComponentCert = coreComponentCert.getCertificate().getX509();
                    } catch (CertificateException e) {
                        log.error(e);
                        throw new SecurityException(e.getMessage(), e.getCause());
                    }
                    if (x509CoreComponentCert.getPublicKey().equals(certFromCSR.getPublicKey())) {
                        componentCertificatesRepository.save(new ComponentCertificate(componentId, new Certificate(pem)));
                    } else {
                        RevocationRequest revocationRequest = new RevocationRequest();
                        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
                        revocationRequest.setCredentials(new Credentials(certificateRequest.getUsername(), certificateRequest.getPassword()));
                        revocationRequest.setCertificateCommonName(componentId + illegalSign + platformId);
                        if (!revocationService.revoke(revocationRequest).isRevoked()) {
                            throw new SecurityException();
                        }
                        componentCertificatesRepository.save(new ComponentCertificate(componentId, new Certificate(pem)));
                    }
                } else {
                    componentCertificatesRepository.save(new ComponentCertificate(componentId, new Certificate(pem)));
                }
            }
        } else {
            // platform component
            Platform platform = platformRepository.findOne(platformId);

            Certificate platformComponentCert = platform.getComponentCertificates().get(componentId);
            if (platformComponentCert != null) {
                X509Certificate x509PlatformComponentCert;
                try {
                    x509PlatformComponentCert = platformComponentCert.getX509();
                } catch (CertificateException e) {
                    log.error(e);
                    throw new SecurityException(e.getMessage(), e.getCause());
                }
                if (x509PlatformComponentCert.getPublicKey().equals(certFromCSR.getPublicKey())) {
                    platform.getComponentCertificates().replace(componentId, new Certificate(pem));
                } else {

                    RevocationRequest revocationRequest = new RevocationRequest();
                    revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
                    revocationRequest.setCredentials(new Credentials(certificateRequest.getUsername(), certificateRequest.getPassword()));
                    revocationRequest.setCertificateCommonName(componentId + illegalSign + platformId);
                    if (!revocationService.revoke(revocationRequest).isRevoked()) {
                        throw new SecurityException();
                    }
                    platform.getComponentCertificates().put(componentId, new Certificate(pem));
                }
            } else {
                platform.getComponentCertificates().put(componentId, new Certificate(pem));
            }
            platformRepository.save(platform);
        }
    }

    private void putPlatformCertToRepository(PKCS10CertificationRequest req, CertificateRequest certificateRequest,
                                             String pem, X509Certificate certFromCSR) {

        String platformId = req.getSubject().toString().split("CN=")[1];
        Platform platform = platformRepository.findOne(platformId);

        Certificate platformCert = platform.getPlatformAAMCertificate();
        if (!platformCert.getCertificateString().isEmpty()) {
            X509Certificate x509PlatformCert;
            try {
                x509PlatformCert = platformCert.getX509();
            } catch (CertificateException e) {
                log.error(e);
                throw new SecurityException(e.getMessage(), e.getCause());
            }
            if (x509PlatformCert.getPublicKey().equals(certFromCSR.getPublicKey())) {
                platform.setPlatformAAMCertificate(new Certificate(pem));
            } else {

                RevocationRequest revocationRequest = new RevocationRequest();
                revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
                revocationRequest.setCredentials(new Credentials(certificateRequest.getUsername(), certificateRequest.getPassword()));
                revocationRequest.setCertificateCommonName(platformId);
                if (!revocationService.revoke(revocationRequest).isRevoked()) {
                    throw new SecurityException();
                }
                platform.setPlatformAAMCertificate(new Certificate(pem));
            }
        } else {
            platform.setPlatformAAMCertificate(new Certificate(pem));
        }
        platformRepository.save(platform);
    }

    private void putUserCertToRepository(User user, CertificateRequest certificateRequest, X509Certificate certFromCSR,
                                         String pem) {

        Certificate userCert = user.getClientCertificates().get(certificateRequest.getClientId());
        if (userCert != null) {
            X509Certificate x509UserCert;
            try {
                x509UserCert = userCert.getX509();
            } catch (CertificateException e) {
                log.error(e);
                throw new SecurityException(e.getMessage(), e.getCause());
            }
            if (x509UserCert.getPublicKey().equals(certFromCSR.getPublicKey())) {

                user.getClientCertificates().replace(certificateRequest.getClientId(), new Certificate(pem));
            } else {
                RevocationRequest revocationRequest = new RevocationRequest();
                revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
                revocationRequest.setCredentials(new Credentials(certificateRequest.getUsername(), certificateRequest.getPassword()));
                revocationRequest.setCertificateCommonName(user.getUsername() + illegalSign + certificateRequest.getClientId());
                if (!revocationService.revoke(revocationRequest).isRevoked()) {
                    throw new SecurityException();
                }
                user.getClientCertificates().put(certificateRequest.getClientId(), new Certificate(pem));
            }
        } else {
            user.getClientCertificates().put(certificateRequest.getClientId(), new Certificate(pem));
        }
        userRepository.save(user);
    }

    private X509Certificate createCertificateFromCSR(CertificateRequest certificateRequest, PKCS10CertificationRequest req) throws
            InvalidArgumentsException, UserManagementException, PlatformManagementException {
        X509Certificate certFromCSR;

        //platform
        if (!req.getSubject().toString().split("CN=")[1].contains(illegalSign)) {
            certFromCSR = createPlatformCertFromCSR(certificateRequest, req);
        }
        //platform component
        else if (req.getSubject().toString().matches("(CN=)(\\w+)(@)(\\w+)")) {
            certFromCSR = createPlatformComponentCertFromCSR(certificateRequest, req);
        }
        //user
        else {
            certFromCSR = createUserCertFromCSR(req);
        }
        return certFromCSR;
    }

    private X509Certificate createUserCertFromCSR(PKCS10CertificationRequest req)
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


    private X509Certificate createPlatformCertFromCSR(CertificateRequest certificateRequest, PKCS10CertificationRequest req)
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

    private X509Certificate createPlatformComponentCertFromCSR(CertificateRequest certificateRequest, PKCS10CertificationRequest req)
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
            NotExistingUserException,
            ValidationException {

        User user = userRepository.findOne(certificateRequest.getUsername());

        if (user == null)
            throw new NotExistingUserException();

        if (!certificateRequest.getPassword().equals(user.getPasswordEncrypted()) &&
                !passwordEncoder.matches(certificateRequest.getPassword(), user.getPasswordEncrypted()))
            throw new WrongCredentialsException();

        try {
            PKCS10CertificationRequest request = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());
            SubjectPublicKeyInfo pkInfo = request.getSubjectPublicKeyInfo();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PublicKey pubKey = converter.getPublicKey(pkInfo);
            if (revokedKeysRepository.findOne(user.getUsername()) != null
                    && revokedKeysRepository.findOne(user.getUsername()).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pubKey.getEncoded()))) {
                throw new ValidationException("Key revoked");
            }
        } catch (IOException e) {
            throw new SecurityException();
        }
        return user;
    }

    private void platformRequestCheck(CertificateRequest certificateRequest) throws
            PlatformManagementException {
        PKCS10CertificationRequest request = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());
        if (userRepository.findOne(certificateRequest.getUsername()).getRole() != UserRole.PLATFORM_OWNER) {
            throw new PlatformManagementException("User is not a Platform Owner", HttpStatus.UNAUTHORIZED);
        }
        if (!platformRepository.exists(request.getSubject().toString().split("CN=")[1])) {
            throw new PlatformManagementException("Platform doesn't exist", HttpStatus.UNAUTHORIZED);
        }
    }

    private void platformComponentRequestCheck(CertificateRequest certificateRequest) throws
            PlatformManagementException {
        PKCS10CertificationRequest request = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());
        if (userRepository.findOne(certificateRequest.getUsername()).getRole() != UserRole.PLATFORM_OWNER) {
            throw new PlatformManagementException("User is not a Platform Owner", HttpStatus.UNAUTHORIZED);
        }
        if (!platformRepository.exists(request.getSubject().toString().split("CN=")[1].split(illegalSign)[1])) {
            throw new PlatformManagementException("Platform doesn't exist", HttpStatus.UNAUTHORIZED);
        }
    }
}