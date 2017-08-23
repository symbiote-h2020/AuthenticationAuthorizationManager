package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
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
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

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
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), usernameWithAt, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        AAMClient.getClientCertificate(certRequest);
    }

    @Test(expected = NotExistingUserException.class)
    public void getClientCertificateOverRESTNotExistingUser() throws
            WrongCredentialsException, NotExistingUserException, ValidationException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            OperatorCreationException,
            InvalidArgumentsException {

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        AAMClient.getClientCertificate(certRequest);
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

        AvailableAAMsCollection aamResponse = AAMClient.getAvailableAAMs();
        KeyPair pair = CryptoHelper.createKeyPair();
        AAM homeAAM = aamResponse.getAvailableAAMs().entrySet().iterator().next().getValue();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getAamCACertificate().getX509(), username, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String clientCertificate = AAMClient.getClientCertificate(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + username + "@" + clientId + "@" + homeAAM.getAamInstanceId(), x509Certificate.getSubjectDN().getName());
    }

    @Test
    public void revokeClientCertificateOverREST() throws
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

        AvailableAAMsCollection aamResponse = AAMClient.getAvailableAAMs();
        KeyPair pair = CryptoHelper.createKeyPair();
        AAM homeAAM = aamResponse.getAvailableAAMs().entrySet().iterator().next().getValue();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getAamCACertificate().getX509(), username, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String clientCertificate = AAMClient.getClientCertificate(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + username + "@" + clientId + "@" + homeAAM.getAamInstanceId(), x509Certificate.getSubjectDN().getName());

        csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getAamCACertificate().getX509(), username, clientId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(username, password, clientId, csrString);
        clientCertificate = AAMClient.getClientCertificate(certRequest);
        x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + username + "@" + clientId + "@" + homeAAM.getAamInstanceId(), x509Certificate.getSubjectDN().getName());
    }

    @Test(expected = ValidationException.class)
    public void getClientCertificateFailsForIncorrectCredentials()
            throws InvalidArgumentsException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException,
            WrongCredentialsException, NotExistingUserException,
            CertificateException, IOException, ValidationException {

        User user = new User();
        user.setUsername(username);
        user.setPasswordEncrypted(passwordEncoder.encode(password));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.USER);
        userRepository.save(user);

        AvailableAAMsCollection aamResponse = AAMClient.getAvailableAAMs();
        KeyPair pair = CryptoHelper.createKeyPair();
        AAM homeAAM = aamResponse.getAvailableAAMs().entrySet().iterator().next().getValue();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getAamCACertificate().getX509(), username, clientId, pair);
        assertNotNull(csrString);
        //  Attempt login with incorrect password
        AAMClient.getClientCertificate(new CertificateRequest
                (username, wrongpassword, clientId, csrString));
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

        Platform platform = new Platform("platformInstanceId", null, null, platformOwner, null, null);
        platformRepository.save(platform);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platform.getPlatformInstanceId(), pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);

        String clientCertificate = AAMClient.getClientCertificate(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platform.getPlatformInstanceId(), x509Certificate.getSubjectDN().getName());
    }

    @Test
    public void replacePlatformAAMCertificateOverRESTSuccess() throws
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

        Platform platform = new Platform("platformInstanceId", null, null, platformOwner, null, null);
        platformRepository.save(platform);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platform.getPlatformInstanceId(), pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);

        String clientCertificate = AAMClient.getClientCertificate(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platform.getPlatformInstanceId(), x509Certificate.getSubjectDN().getName());

        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platform.getPlatformInstanceId(), pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        clientCertificate = AAMClient.getClientCertificate(certRequest);

        X509Certificate x509CertificateNew = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509CertificateNew);
        assertEquals("CN=" + platform.getPlatformInstanceId(), x509CertificateNew.getSubjectDN().getName());
        System.out.println(x509Certificate);
        assertNotEquals(x509Certificate, x509CertificateNew);

    }
}
