package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.cert.CertificateException;

@Service
public class RevocationService {
    private RevocationHelper revocationHelper;

    @Autowired
    public RevocationService(RevocationHelper revocationHelper) {
        this.revocationHelper = revocationHelper;
    }

    //TODO exceptions modification
    //TODO revocationHelper functions
    public void revoke(RevocationRequest revocationRequest) throws WrongCredentialsException, ValidationException, CertificateException, NotExistingUserException, IOException {
        switch (revocationRequest.getCredentialType()) {
            case USER:
                if (!revocationRequest.getCertificatePEMString().isEmpty() ||
                        !revocationRequest.getCertificateCommonName().isEmpty()) {
                    revocationHelper.revokeCertificate(revocationRequest.getCredentials(), new Certificate(revocationRequest.getCertificatePEMString()), revocationRequest.getCertificatePEMString());
                } else if (!revocationRequest.getHomeTokenString().isEmpty()) {
                    revocationHelper.revokeHomeToken(revocationRequest.getCredentials(), new Token(revocationRequest.getHomeTokenString()));
                } else {
                    throw new SecurityException();
                }
                break;
            case ADMIN:
                if (!revocationRequest.getHomeTokenString().isEmpty()) {
                    revocationHelper.revokeHomeToken(revocationRequest.getCredentials(), new Token(revocationRequest.getHomeTokenString()));
                } else if (!revocationRequest.getCertificatePEMString().isEmpty() ||
                        !revocationRequest.getCertificateCommonName().isEmpty()) {
                    revocationHelper.revokeCertificate(revocationRequest.getCredentials(), new Certificate(revocationRequest.getCertificatePEMString()), revocationRequest.getCertificateCommonName());
                } else {
                    throw new SecurityException();
                }
                break;
            case NULL:
                if (revocationRequest.getHomeTokenString().isEmpty() ||
                        revocationRequest.getForeignTokenString().isEmpty()) {
                    throw new SecurityException();
                }
                revocationHelper.revokeForeignToken(new Token(revocationRequest.getHomeTokenString()), new Token(revocationRequest.getForeignTokenString()));
                break;
        }
    }


}
