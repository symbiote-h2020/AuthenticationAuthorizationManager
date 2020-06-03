package eu.h2020.symbiote.security.services;

import java.io.IOException;
import java.security.cert.CertificateException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationResponse;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;

/**
 * Spring service used to revoke tokens and certificates.
 * * @author Jakub Toczek (PSNC)
 */

@Service
public class RevocationService {
    private static Log log = LogFactory.getLog(RevocationService.class);
    private final RevocationHelper revocationHelper;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;

    @Autowired
    public RevocationService(RevocationHelper revocationHelper, PasswordEncoder passwordEncoder, UserRepository userRepository) {
        this.passwordEncoder = passwordEncoder;
        this.revocationHelper = revocationHelper;
        this.userRepository = userRepository;
    }

    public RevocationResponse revoke(RevocationRequest revocationRequest) {
        try {
            switch (revocationRequest.getCredentialType()) {
                case USER:
                    return userRevoke(revocationRequest);
                case ADMIN:
                    return adminRevoke(revocationRequest);
                case NULL:
                    return noCredentialTypeRevoke(revocationRequest);
                default:
                    return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
            }
        } catch (CertificateException | IOException | IllegalArgumentException | InvalidArgumentsException | SecurityException e) {
            log.error(e.getMessage());
            return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
        } catch (WrongCredentialsException | ValidationException | NotExistingUserException | MalformedJWTException | SecurityMisconfigurationException e) {
            log.error(e.getMessage());
            return new RevocationResponse(false, e.getStatusCode());
        }
    }

    private RevocationResponse noCredentialTypeRevoke(RevocationRequest revocationRequest) throws
            ValidationException,
            MalformedJWTException,
            SecurityMisconfigurationException {
        if (revocationRequest.getHomeTokenString().isEmpty()
                || revocationRequest.getForeignTokenString().isEmpty()) {
            log.error(InvalidArgumentsException.REQUEST_IS_INCORRECTLY_BUILT);
            return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
        }
        return new RevocationResponse(revocationHelper.revokeForeignToken(new Token(revocationRequest.getHomeTokenString()), new Token(revocationRequest.getForeignTokenString())), HttpStatus.OK);
    }

    private RevocationResponse adminRevoke(RevocationRequest revocationRequest) throws
            ValidationException,
            WrongCredentialsException,
            CertificateException,
            MalformedJWTException,
            IOException,
            NotExistingUserException,
            InvalidArgumentsException {
        if (!revocationRequest.getCredentials().getUsername().equals(AAMOwnerUsername)
                || !passwordEncoder.matches(revocationRequest.getCredentials().getPassword(), passwordEncoder.encode(AAMOwnerPassword))) {
            log.error(WrongCredentialsException.AUTHENTICATION_OF_USER_FAILED);
            return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
        }
        if (!revocationRequest.getHomeTokenString().isEmpty()) {
            return new RevocationResponse(this.revocationHelper.revokeHomeTokenByAdmin(revocationRequest.getHomeTokenString()), HttpStatus.OK);
        }
        if (!revocationRequest.getCertificatePEMString().isEmpty()
                || !revocationRequest.getCertificateCommonName().isEmpty()) {
            return new RevocationResponse(this.revocationHelper.revokeCertificateByAdmin(new Certificate(revocationRequest.getCertificatePEMString()), revocationRequest.getCertificateCommonName()), HttpStatus.OK);
        }
        log.error(InvalidArgumentsException.REQUEST_IS_INCORRECTLY_BUILT);
        return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
    }

    private RevocationResponse userRevoke(RevocationRequest revocationRequest) throws
            CertificateException,
            NotExistingUserException,
            WrongCredentialsException,
            ValidationException,
            IOException,
            InvalidArgumentsException {
        if (revocationRequest.getCredentials().getUsername().isEmpty()) {
            throw new WrongCredentialsException(WrongCredentialsException.AUTHENTICATION_OF_USER_FAILED);
        }
        User user = userRepository.findById(revocationRequest.getCredentials().getUsername()).orElseGet(() -> null);
        if (user == null || user.getRole() == UserRole.NULL) {
            throw new NotExistingUserException(NotExistingUserException.AUTHENTICATION_OF_USER_FAILED);
        }
        if (!passwordEncoder.matches(revocationRequest.getCredentials().getPassword(), user.getPasswordEncrypted())) {
            throw new WrongCredentialsException(WrongCredentialsException.AUTHENTICATION_OF_USER_FAILED);
        }
        if (user.getStatus() != AccountStatus.ACTIVE)
            throw new WrongCredentialsException(WrongCredentialsException.USER_NOT_ACTIVE, HttpStatus.FORBIDDEN);
        if (!revocationRequest.getCertificatePEMString().isEmpty() ||
                !revocationRequest.getCertificateCommonName().isEmpty()) {
            return new RevocationResponse(revocationHelper.revokeCertificate(user, new Certificate(revocationRequest.getCertificatePEMString()), revocationRequest.getCertificateCommonName()), HttpStatus.OK);
        }
        if (!revocationRequest.getHomeTokenString().isEmpty()) {
            return new RevocationResponse(revocationHelper.revokeHomeToken(user, new Token(revocationRequest.getHomeTokenString())), HttpStatus.OK);
        }

        throw new InvalidArgumentsException(InvalidArgumentsException.REQUEST_IS_INCORRECTLY_BUILT);
    }

}
