package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@TestPropertySource("/core.properties")
public class ClientCertificatesIssuingFunctionalTests extends
        AbstractAAMTestSuite {

    @Test(expected = InvalidArgumentsException.class)
    public void getClientCertificateOverRESTInvalidArguments() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            OperatorCreationException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException {
        KeyPair pair = CryptoHelper.createKeyPair();
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal(certificationAuthorityHelper.getAAMCertificate().getSubjectX500Principal().getName()), pair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(pair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(usernameWithAt, password, clientId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        restaamClient.getClientCertificate(certRequest);

    }

    @Test
    public void getClientCertificateOverRESTSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            IOException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException {

        User user = new User();
        user.setUsername(username);
        user.setPasswordEncrypted(passwordEncoder.encode(password));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.USER);
        userRepository.save(user);

        AvailableAAMsCollection aamResponse = restaamClient.getAvailableAAMs();
        KeyPair pair = CryptoHelper.createKeyPair();
        AAM homeAAM = aamResponse.getAvailableAAMs().entrySet().iterator().next().getValue();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getCertificate().getX509(), username, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String clientCertificate = restaamClient.getClientCertificate(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + username + "@" + clientId + "@" + homeAAM.getAamInstanceId(), x509Certificate.getSubjectDN().getName());
    }

    @Test
    public void getPlatformAAMCertificateOverRESTSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            CertificateException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException {

        User platformOwner = savePlatformOwner();

        Platform platform = new Platform("platformInstanceId", null, null, platformOwner, null);
        platformRepository.save(platform);

        KeyPair pair = CryptoHelper.createKeyPair();
        restaamClient.getAvailableAAMs().getAvailableAAMs().entrySet().iterator().next().getValue();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platform.getPlatformInstanceId(), pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);

        String clientCertificate = restaamClient.getClientCertificate(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platform.getPlatformInstanceId(), x509Certificate.getSubjectDN().getName());
    }
}
