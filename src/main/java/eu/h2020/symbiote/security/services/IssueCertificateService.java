package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.*;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
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
 * @author Mikołaj Dobski (PSNC)
 */

@Service
public class IssueCertificateService {
    private static final Log log = LogFactory.getLog(IssueCertificateService.class);
    private final UserRepository userRepository;
    private final PlatformRepository platformRepository;
    private final SmartSpaceRepository smartSpaceRepository;
    private final RevokedKeysRepository revokedKeysRepository;
    private final ComponentCertificatesRepository componentCertificatesRepository;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final PasswordEncoder passwordEncoder;
    private final AAMServices aamServices;
    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;

    @Autowired
    public IssueCertificateService(UserRepository userRepository,
                                   PlatformRepository platformRepository,
                                   SmartSpaceRepository smartSpaceRepository,
                                   RevokedKeysRepository revokedKeysRepository,
                                   ComponentCertificatesRepository componentCertificatesRepository,
                                   CertificationAuthorityHelper certificationAuthorityHelper,
                                   PasswordEncoder passwordEncoder,
                                   AAMServices aamServices) {
        this.userRepository = userRepository;
        this.platformRepository = platformRepository;
        this.smartSpaceRepository = smartSpaceRepository;
        this.revokedKeysRepository = revokedKeysRepository;
        this.componentCertificatesRepository = componentCertificatesRepository;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.passwordEncoder = passwordEncoder;
        this.aamServices = aamServices;
    }

    public String signCertificate(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException,
            InvalidArgumentsException,
            UserManagementException,
            ServiceManagementException,
            ValidationException,
            CertificateException {

        String pem;
        PKCS10CertificationRequest request = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());
        User user = validateRequest(certificateRequest);

        // symbiote components
        if (request.getSubject().toString().matches("^(CN=)(([\\w-])+)(@)(([\\w-])+)$")) {
            X509Certificate certFromCSR = createComponentCertFromCSR(request);
            pem = createPem(certFromCSR);
            persistComponentCertificate(request, pem);
        }
        // platform / smartSpace
        else if (request.getSubject().toString().matches("^(CN=)(([\\w-])+)$")) {
            X509Certificate certFromCSR = createServiceCertFromCSR(request);
            pem = createPem(certFromCSR);
            persistServiceCertificate(request, pem);
        }
        // user / platform owner
        else if (request.getSubject().toString().matches("^(CN=)(([\\w-])+)(@)(([\\w-])+)(@)(([\\w-])+)$")) {
            if (user == null) {
                throw new ValidationException(ValidationException.USER_NOT_FOUND_IN_DB);
            }
            X509Certificate certFromCSR = createUserCertFromCSR(request);
            pem = createPem(certFromCSR);
            persistUserCertificate(user, certificateRequest, pem);
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

    private User validateRequest(CertificateRequest certificateRequest) throws
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            ServiceManagementException {

        User user = null;
        PublicKey pubKey;
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
        //TODO SAAM accepts serviceOwner accounts
        if (certificateRequest.getUsername().equals(AAMOwnerUsername)) {
            // password check
            if (!certificateRequest.getPassword().equals(AAMOwnerPassword))
                throw new WrongCredentialsException();
            //deployment id check
            if (!certificationAuthorityHelper.getAAMInstanceIdentifier().equals(request.getSubject().toString().split("CN=")[1].split(illegalSign)[1]))
                throw new ValidationException(ValidationException.WRONG_DEPLOYMENT_ID);
            if (revokedKeysRepository.exists(certificationAuthorityHelper.getAAMInstanceIdentifier())
                    && revokedKeysRepository.findOne(certificationAuthorityHelper.getAAMInstanceIdentifier()).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pubKey.getEncoded()))) {
                throw new ValidationException(ValidationException.USING_REVOKED_KEY);
            }
            componentRequestCheck(certificateRequest);
        }
        // services path (platform, enabler, smartSpace)
        else if (request.getSubject().toString().matches("^(CN=)(([\\w-])+)$")) {
            if (revokedKeysRepository.exists(request.getSubject().toString().split("CN=")[1])
                    && revokedKeysRepository.findOne(request.getSubject().toString().split("CN=")[1]).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pubKey.getEncoded()))) {
                throw new ValidationException(ValidationException.USING_REVOKED_KEY);
            }
            serviceRequestCheck(certificateRequest);
        } else {
            user = userRepository.findOne(certificateRequest.getUsername());
            if (user == null)
                throw new NotExistingUserException();
            if (!certificateRequest.getPassword().equals(user.getPasswordEncrypted()) &&
                    !passwordEncoder.matches(certificateRequest.getPassword(), user.getPasswordEncrypted()))
                throw new WrongCredentialsException();
            if (!certificationAuthorityHelper.getAAMInstanceIdentifier().equals(request.getSubject().toString().split("CN=")[1].split(illegalSign)[2]))
                throw new ValidationException(ValidationException.WRONG_DEPLOYMENT_ID);
            if (revokedKeysRepository.exists(user.getUsername())
                    && revokedKeysRepository.findOne(user.getUsername()).getRevokedKeysSet().contains(Base64.getEncoder().encodeToString(pubKey.getEncoded()))) {
                throw new ValidationException(ValidationException.USING_REVOKED_KEY);
            }
        }

        return user;
    }

    private void persistComponentCertificate(PKCS10CertificationRequest req,
                                             String pem) throws CertificateException {

        String componentId = req.getSubject().toString().split("CN=")[1].split("@")[0];
        String platformId = req.getSubject().toString().split("CN=")[1].split("@")[1];

        componentCertificatesRepository.save(new ComponentCertificate(componentId, new Certificate(pem)));
        aamServices.invalidateComponentCertificateCache(componentId, platformId);
        aamServices.invalidateAvailableAAMsCache();
        aamServices.invalidateInternalAAMsCache();
    }

    private void persistServiceCertificate(PKCS10CertificationRequest req,
                                           String pem) throws CertificateException {

        String serviceId = req.getSubject().toString().split("CN=")[1];
        if (serviceId.startsWith(SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX)) {
            SmartSpace smartSpace = smartSpaceRepository.findOne(serviceId);
            smartSpace.setAamCertificate(new Certificate(pem));
            smartSpaceRepository.save(smartSpace);
        } else {
            Platform platform = platformRepository.findOne(serviceId);
            platform.setPlatformAAMCertificate(new Certificate(pem));
            platformRepository.save(platform);
        }
        aamServices.invalidateComponentCertificateCache(SecurityConstants.AAM_COMPONENT_NAME, serviceId);
        aamServices.invalidateAvailableAAMsCache();
        aamServices.invalidateInternalAAMsCache();
    }

    private void persistUserCertificate(User user,
                                        CertificateRequest certificateRequest,
                                        String pem) throws CertificateException {

        user.getClientCertificates().put(certificateRequest.getClientId(), new Certificate(pem));
        userRepository.save(user);
    }

    private X509Certificate createUserCertFromCSR(PKCS10CertificationRequest req)
            throws UserManagementException {
        X509Certificate certFromCSR;

        try {
            certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        } catch (CertificateException e) {
            log.error(e);
            throw new UserManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return certFromCSR;
    }


    private X509Certificate createServiceCertFromCSR(PKCS10CertificationRequest req)
            throws ServiceManagementException {
        X509Certificate certFromCSR;
        try {
            certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, true);
        } catch (CertificateException e) {
            log.error(e);
            //TODO do sth with the error (SMART_SPACE)
            throw new ServiceManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return certFromCSR;
    }

    private X509Certificate createComponentCertFromCSR(PKCS10CertificationRequest req)
            throws ServiceManagementException {
        X509Certificate certFromCSR;
        try {
            certFromCSR = certificationAuthorityHelper.generateCertificateFromCSR(req, false);
        } catch (CertificateException e) {
            log.error(e);
            throw new ServiceManagementException(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return certFromCSR;
    }

    private void serviceRequestCheck(CertificateRequest certificateRequest) throws
            ServiceManagementException,
            NotExistingUserException {
        PKCS10CertificationRequest request = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());
        if (!userRepository.exists(certificateRequest.getUsername()))
            throw new NotExistingUserException();
        User user = userRepository.findOne(certificateRequest.getUsername());
        if (user.getRole() != UserRole.SERVICE_OWNER
                || !user.getOwnedServices().contains(request.getSubject().toString().split("CN=")[1])) {
            throw new ServiceManagementException(ServiceManagementException.NO_RIGHTS, HttpStatus.UNAUTHORIZED);
        }
        if (request.getSubject().toString().split("CN=")[1].startsWith(SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX)) {
            smartSpaceRequestCheck(request);
        } else {
            platformRequestCheck(request);
        }
    }

    private void platformRequestCheck(PKCS10CertificationRequest request) throws
            ServiceManagementException {
        if (!platformRepository.exists(request.getSubject().toString().split("CN=")[1])) {
            throw new ServiceManagementException(ServiceManagementException.SERVICE_NOT_EXIST, HttpStatus.UNAUTHORIZED);
        }
    }

    private void smartSpaceRequestCheck(PKCS10CertificationRequest request) throws ServiceManagementException {
        if (!smartSpaceRepository.exists(request.getSubject().toString().split("CN=")[1])) {
            throw new ServiceManagementException(ServiceManagementException.SERVICE_NOT_EXIST, HttpStatus.UNAUTHORIZED);
        }
    }

    private void componentRequestCheck(CertificateRequest certificateRequest) throws
            ServiceManagementException {
        PKCS10CertificationRequest request = CryptoHelper.convertPemToPKCS10CertificationRequest(certificateRequest.getClientCSRinPEMFormat());
        // component id must not be AAM
        if (request.getSubject().toString().split("CN=")[1].split(illegalSign)[0].equals(SecurityConstants.AAM_COMPONENT_NAME))
            throw new ServiceManagementException(ServiceManagementException.WRONG_WAY_TO_ISSUE_AAM_CERTIFICATE, HttpStatus.BAD_REQUEST);
    }
}