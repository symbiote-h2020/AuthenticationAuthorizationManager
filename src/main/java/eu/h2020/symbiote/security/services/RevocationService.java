package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationResponse;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateException;

/**
 * Spring service used to revoke tokens and certificates.
 * * @author Jakub Toczek (PSNC)
 */

@Service
public class RevocationService {
    private RevocationHelper revocationHelper;

    @Autowired
    public RevocationService(RevocationHelper revocationHelper) {
        this.revocationHelper = revocationHelper;
    }

    public RevocationResponse revoke(RevocationRequest revocationRequest) {
        try {
            switch (revocationRequest.getCredentialType()) {
                case USER:
                    if (!revocationRequest.getCertificatePEMString().isEmpty() ||
                            !revocationRequest.getCertificateCommonName().isEmpty()) {
                        revocationHelper.revokeCertificate(revocationRequest.getCredentials(), new Certificate(revocationRequest.getCertificatePEMString()), revocationRequest.getCertificateCommonName());
                        return new RevocationResponse(true, HttpStatus.OK);
                    } else if (!revocationRequest.getHomeTokenString().isEmpty()) {
                        revocationHelper.revokeHomeToken(revocationRequest.getCredentials(), new Token(revocationRequest.getHomeTokenString()));
                        return new RevocationResponse(true, HttpStatus.OK);
                    } else {
                        throw new WrongCredentialsException();
                    }
                case ADMIN:
                    if (!revocationRequest.getHomeTokenString().isEmpty()) {
                        revocationHelper.revokeHomeToken(revocationRequest.getCredentials(), new Token(revocationRequest.getHomeTokenString()));
                        return new RevocationResponse(true, HttpStatus.OK);
                    } else if (!revocationRequest.getCertificatePEMString().isEmpty() ||
                            !revocationRequest.getCertificateCommonName().isEmpty()) {
                        revocationHelper.revokeCertificateAdmin(revocationRequest.getCredentials(), new Certificate(revocationRequest.getCertificatePEMString()), revocationRequest.getCertificateCommonName());
                        return new RevocationResponse(true, HttpStatus.OK);
                    } else {
                        return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
                    }
                case NULL:
                    if (revocationRequest.getHomeTokenString().isEmpty() ||
                            revocationRequest.getForeignTokenString().isEmpty()) {
                        return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
                    }
                    revocationHelper.revokeForeignToken(new Token(revocationRequest.getHomeTokenString()), new Token(revocationRequest.getForeignTokenString()));
                    return new RevocationResponse(true, HttpStatus.OK);
            }
        } catch (CertificateException e) {
            return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
        } catch (WrongCredentialsException | ValidationException | NotExistingUserException e) {
            return new RevocationResponse(false, e.getStatusCode());
        }
        return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
    }

}
