package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationResponse;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

/**
 * Spring service used to revoke tokens and certificates.
 * * @author Jakub Toczek (PSNC)
 */

@Service
public class RevocationService {
    private final RevocationHelper revocationHelper;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private static Log log = LogFactory.getLog(RevocationService.class);

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
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | NoSuchProviderException | IOException | IllegalArgumentException | SecurityException e) {
            log.error(e.getMessage());
            return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
        } catch (WrongCredentialsException | ValidationException | NotExistingUserException | MalformedJWTException e) {
            log.error(e.getMessage());
            return new RevocationResponse(false, e.getStatusCode());
        }
    }

    private RevocationResponse noCredentialTypeRevoke(RevocationRequest revocationRequest) throws ValidationException, CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, MalformedJWTException, IOException {
        if (revocationRequest.getHomeTokenString().isEmpty()
                || revocationRequest.getForeignTokenString().isEmpty()) {
            log.error("Acquired Revocation Request is incorrectly built");
            return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
        }
        return new RevocationResponse(revocationHelper.revokeForeignToken(new Token(revocationRequest.getHomeTokenString()), new Token(revocationRequest.getForeignTokenString())), HttpStatus.OK);
    }

    private RevocationResponse adminRevoke(RevocationRequest revocationRequest) throws ValidationException, WrongCredentialsException, CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, MalformedJWTException, IOException, NotExistingUserException {
        if (!revocationRequest.getCredentials().getUsername().equals(AAMOwnerUsername)
                || !passwordEncoder.matches(revocationRequest.getCredentials().getPassword(), passwordEncoder.encode(AAMOwnerPassword))) {
            log.error("Authentication of AAM owner failed");
            return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
        }
        if (!revocationRequest.getHomeTokenString().isEmpty()) {
            return new RevocationResponse(this.revocationHelper.revokeHomeTokenByAdmin(revocationRequest.getHomeTokenString()), HttpStatus.OK);
        }
        if (!revocationRequest.getCertificatePEMString().isEmpty()
                || !revocationRequest.getCertificateCommonName().isEmpty()) {
            return new RevocationResponse(this.revocationHelper.revokeCertificateByAdmin(new Certificate(revocationRequest.getCertificatePEMString()), revocationRequest.getCertificateCommonName()), HttpStatus.OK);
        }
        log.error("Acquired Revocation Request is incorrectly built");
        return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
    }

    private RevocationResponse userRevoke(RevocationRequest revocationRequest) throws CertificateException, NotExistingUserException, WrongCredentialsException, ValidationException, IOException {
        if (revocationRequest.getCredentials().getUsername().isEmpty()) {
            throw new WrongCredentialsException("Authentication of user failed");
        }
        User user = userRepository.findOne(revocationRequest.getCredentials().getUsername());
        if (user == null || user.getRole() == UserRole.NULL) {
            throw new NotExistingUserException("Authentication of user failed");
        }
        if (!passwordEncoder.matches(revocationRequest.getCredentials().getPassword(), user.getPasswordEncrypted())) {
            throw new WrongCredentialsException("Authentication of user failed");
        }
        if (!revocationRequest.getCertificatePEMString().isEmpty() ||
                !revocationRequest.getCertificateCommonName().isEmpty()) {
            return new RevocationResponse(revocationHelper.revokeCertificate(user, new Certificate(revocationRequest.getCertificatePEMString()), revocationRequest.getCertificateCommonName()), HttpStatus.OK);
        }
        if (!revocationRequest.getHomeTokenString().isEmpty()) {
            return new RevocationResponse(revocationHelper.revokeHomeToken(user, new Token(revocationRequest.getHomeTokenString())), HttpStatus.OK);
        }

        throw new WrongCredentialsException("Acquired Revocation Request is incorrectly built");
    }

}
