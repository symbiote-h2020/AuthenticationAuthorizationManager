package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
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

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

/**
 * Spring service used to provide client certificates issuing
 *
 * @author Maksymilian Marcinowski (PSNC)
 * @author Jakub Toczek (PSNC)
 */

@Service
public class SignCertificateRequestService {
    private static final Log log = LogFactory.getLog(SignCertificateRequestService.class);
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
    public SignCertificateRequestService(UserRepository userRepository, PlatformRepository platformRepository,
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

    public String signCertificate(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            UserManagementException,
            PlatformManagementException,
            ValidationException {

        String pem;
        User user = requestValidationCheck(certificateRequest);
        PKCS10CertificationRequest request = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());


        // symbiote components
        if (request.getSubject().toString().matches("^(CN=)(([\\w-])+)(@)(([\\w-])+)$")) {
            X509Certificate certFromCSR = createComponentCertFromCSR(certificateRequest, request);
            pem = createPem(certFromCSR);
            putComponentCertificateToRepository(request, certificateRequest, pem, certFromCSR);
        }
        //platform
        else if (request.getSubject().toString().matches("^(CN=)(([\\w-])+)$")) {
            X509Certificate certFromCSR = createPlatformCertFromCSR(certificateRequest, request);
            pem = createPem(certFromCSR);
            putPlatformCertificateToRepository(request, certificateRequest, pem, certFromCSR);
        }
        // user / platform owner
        else if (request.getSubject().toString().matches("^(CN=)(([\\w-])+)(@)(([\\w-])+)(@)(([\\w-])+)$")) {
            X509Certificate certFromCSR = createUserCertFromCSR(request);
            pem = createPem(certFromCSR);
            putUserCertificateToRepository(user, certificateRequest, certFromCSR, pem);
        } else {
            throw new InvalidArgumentsException();
        }
        return pem;
    }

    private String createPem(X509Certificate certFromCSR) {
        String pem;
        try {
            pem = CryptoHelper.convertX509ToPEM(certFromCSR);
        } catch (IOException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }
        return pem;
    }

    private User requestValidationCheck(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException {

        User user = null;
        PublicKey pubKey = null;
        PKCS10CertificationRequest request;
        try {
            request = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());
            SubjectPublicKeyInfo pkInfo = request.getSubjectPublicKeyInfo();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            pubKey = converter.getPublicKey(pkInfo);
        } catch (IOException e) {
            throw new SecurityException();
        }

        // component path
        if (certificateRequest.getUsername().equals(AAMOwnerUsername)) {
            // password check
            if (!certificateRequest.getPassword().equals(AAMOwnerPassword))
                throw new WrongCredentialsException();
            //deployment id check
            if (!certificationAuthorityHelper.getAAMInstanceIdentifier().equals(request.getSubject().toString().split("CN=")[1].split("@")[1]))
                throw new ValidationException("Deployment id's mismatch");
            if (revokedKeysRepository.exists(certificationAuthorityHelper.getAAMInstanceIdentifier())
                    && revokedKeysRepository.findOne(certificationAuthorityHelper.getAAMInstanceIdentifier()).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pubKey.getEncoded()))) {
                throw new ValidationException("Using revoked key");
            }
        } else {
            user = userRepository.findOne(certificateRequest.getUsername());
            if (user == null)
                throw new NotExistingUserException();

            if (!certificateRequest.getPassword().equals(user.getPasswordEncrypted()) &&
                    !passwordEncoder.matches(certificateRequest.getPassword(), user.getPasswordEncrypted()))
                throw new WrongCredentialsException();
            if (revokedKeysRepository.exists(user.getUsername())
                    && revokedKeysRepository.findOne(user.getUsername()).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pubKey.getEncoded()))) {
                throw new ValidationException("Using revoked key");
            }
        }
        return user;
    }

    private void putComponentCertificateToRepository(PKCS10CertificationRequest req,
                                                     CertificateRequest certificateRequest,
                                                     String pem,
                                                     X509Certificate certFromCSR) {

        String componentId = req.getSubject().toString().split("CN=")[1].split("@")[0];
        String platformId = req.getSubject().toString().split("CN=")[1].split("@")[1];

        ComponentCertificate componentCert = componentCertificatesRepository.findOne(componentId);
        if (componentCert != null) {
            X509Certificate x509ComponentCert;
            try {
                x509ComponentCert = componentCert.getCertificate().getX509();
            } catch (CertificateException e) {
                log.error(e);
                throw new SecurityException(e.getMessage(), e.getCause());
            }
            if (x509ComponentCert.getPublicKey().equals(certFromCSR.getPublicKey())) {
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

    private void putPlatformCertificateToRepository(PKCS10CertificationRequest req,
                                                    CertificateRequest certificateRequest,
                                                    String pem,
                                                    X509Certificate certFromCSR) {

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

    private void putUserCertificateToRepository(User user,
                                                CertificateRequest certificateRequest,
                                                X509Certificate certFromCSR,
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

        String platformIdFromCSR = req.getSubject().toString().split("CN=")[1].split("@")[2];
        String aamId = caCert.getSubjectDN().getName().split("CN=")[1];
        if (!platformIdFromCSR.equals(aamId))
            throw new InvalidArgumentsException("CSR CN contains: "+platformIdFromCSR+ "which doesn't match this AAM: "+aamId);

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

    private X509Certificate createComponentCertFromCSR(CertificateRequest certificateRequest, PKCS10CertificationRequest req)
            throws PlatformManagementException {
        X509Certificate certFromCSR;
        componentRequestCheck(certificateRequest);
        try {
            certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        } catch (CertificateException e) {
            log.error(e);
            throw new PlatformManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return certFromCSR;
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

    private void componentRequestCheck(CertificateRequest certificateRequest) throws
            PlatformManagementException {
        PKCS10CertificationRequest request = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());
        // component id must not be AAM
        if (request.getSubject().toString().split("CN=")[1].split(illegalSign)[0].equals(SecurityConstants.AAM_COMPONENT_NAME))
            throw new PlatformManagementException("this is not the way to issue AAM certificate", HttpStatus.BAD_REQUEST);
        String platformIdentifier = request.getSubject().toString().split("CN=")[1].split(illegalSign)[1];
        // only platforms needs to be verified
        if (!platformIdentifier.equals(SecurityConstants.CORE_AAM_INSTANCE_ID)) {
            if (userRepository.findOne(certificateRequest.getUsername()).getRole() != UserRole.PLATFORM_OWNER) {
                throw new PlatformManagementException("User is not a Platform Owner", HttpStatus.UNAUTHORIZED);
            }
            if (!platformRepository.exists(platformIdentifier)) {
                throw new PlatformManagementException("Platform doesn't exist", HttpStatus.UNAUTHORIZED);
            }
        }
    }
}