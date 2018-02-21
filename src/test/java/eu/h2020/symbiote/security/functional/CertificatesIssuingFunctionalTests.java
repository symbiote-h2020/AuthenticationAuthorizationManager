package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.User;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class CertificatesIssuingFunctionalTests extends
        AbstractAAMTestSuite {

    @Test(expected = InvalidArgumentsException.class)
    public void getClientCertificateOverRESTInvalidArguments() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            KeyStoreException,
            IOException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            AAMException {
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), usernameWithAt, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        aamClient.signCertificateRequest(certRequest);
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
            InvalidArgumentsException,
            AAMException {

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(certificationAuthorityHelper.getAAMCertificate(), appUsername, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(appUsername, password, clientId, csrString);
        aamClient.signCertificateRequest(certRequest);
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
            ValidationException,
            AAMException {

        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);

        AvailableAAMsCollection aamResponse = aamClient.getAvailableAAMs();
        KeyPair pair = CryptoHelper.createKeyPair();
        AAM homeAAM = aamResponse.getAvailableAAMs().entrySet().iterator().next().getValue();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getAamCACertificate().getX509(), username, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String clientCertificate = aamClient.signCertificateRequest(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + username + "@" + clientId + "@" + homeAAM.getAamInstanceId(), x509Certificate.getSubjectDN().getName());
    }

    @Test
    public void updateClientCertificateWithTheSameKeyByIssuingNewCertificateOverREST() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            IOException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            AAMException {

        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);

        AvailableAAMsCollection aamResponse = aamClient.getAvailableAAMs();
        KeyPair pair = CryptoHelper.createKeyPair();
        AAM homeAAM = aamResponse.getAvailableAAMs().entrySet().iterator().next().getValue();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getAamCACertificate().getX509(), username, clientId, pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String clientCertificate = aamClient.signCertificateRequest(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + username + "@" + clientId + "@" + homeAAM.getAamInstanceId(), x509Certificate.getSubjectDN().getName());

        csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getAamCACertificate().getX509(), username, clientId, pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(username, password, clientId, csrString);
        clientCertificate = aamClient.signCertificateRequest(certRequest);
        x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + username + "@" + clientId + "@" + homeAAM.getAamInstanceId(), x509Certificate.getSubjectDN().getName());
    }

    @Test(expected = ValidationException.class)
    public void getClientCertificateFailsForIncorrectCredentials()
            throws InvalidArgumentsException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException,
            WrongCredentialsException, NotExistingUserException,
            CertificateException, IOException, ValidationException, AAMException {

        User user = createUser(username, password, recoveryMail, UserRole.USER);
        userRepository.save(user);

        AvailableAAMsCollection aamResponse = aamClient.getAvailableAAMs();
        KeyPair pair = CryptoHelper.createKeyPair();
        AAM homeAAM = aamResponse.getAvailableAAMs().entrySet().iterator().next().getValue();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getAamCACertificate().getX509(), username, clientId, pair);
        assertNotNull(csrString);
        //  Attempt login with incorrect password
        aamClient.signCertificateRequest(new CertificateRequest
                (username, wrongPassword, clientId, csrString));
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
            ValidationException,
            AAMException {

        User platformOwner = savePlatformOwner();

        Platform platform = new Platform(platformId,
                null,
                null,
                platformOwner,
                new Certificate(),
                new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedServices().add(platformId);
        userRepository.save(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platform.getPlatformInstanceId(), pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);

        String clientCertificate = aamClient.signCertificateRequest(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platform.getPlatformInstanceId(), x509Certificate.getSubjectDN().getName());
    }

    @Test
    public void getSmartSpaceAAMCertificateOverRESTSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            IOException,
            CertificateException,
            InvalidArgumentsException,
            WrongCredentialsException,
            NotExistingUserException,
            ValidationException,
            AAMException {

        User smartSpaceOwner = createUser(smartSpaceOwnerUsername, smartSpaceOwnerPassword, recoveryMail, UserRole.SERVICE_OWNER);
        // issue smartSpace registration
        SmartSpace smartSpace = new SmartSpace(preferredSmartSpaceId, smartSpaceExternalInterworkingInterfaceAddress, smartSpaceInternalInterworkingInterfaceAddress, exposedIIAddress, smartSpaceInstanceFriendlyName, new Certificate(), new HashMap<>(), smartSpaceOwner);
        smartSpaceRepository.save(smartSpace);
        smartSpaceOwner.getOwnedServices().add(preferredSmartSpaceId);
        userRepository.save(smartSpaceOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(smartSpace.getSmartSpaceInstanceId(), pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(smartSpaceOwnerUsername, smartSpaceOwnerPassword, clientId, csrString);

        String clientCertificate = aamClient.signCertificateRequest(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + smartSpace.getSmartSpaceInstanceId(), x509Certificate.getSubjectDN().getName());
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
            ValidationException,
            AAMException {

        User platformOwner = savePlatformOwner();

        Platform platform = new Platform(platformId,
                null,
                null,
                platformOwner,
                new Certificate(),
                new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedServices().add(platformId);
        userRepository.save(platformOwner);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platform.getPlatformInstanceId(), pair);
        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);

        String clientCertificate = aamClient.signCertificateRequest(certRequest);
        X509Certificate x509Certificate = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509Certificate);
        assertEquals("CN=" + platform.getPlatformInstanceId(), x509Certificate.getSubjectDN().getName());

        pair = CryptoHelper.createKeyPair();
        csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platform.getPlatformInstanceId(), pair);
        assertNotNull(csrString);
        certRequest = new CertificateRequest(platformOwnerUsername, platformOwnerPassword, clientId, csrString);
        clientCertificate = aamClient.signCertificateRequest(certRequest);

        X509Certificate x509CertificateNew = CryptoHelper.convertPEMToX509(clientCertificate);
        assertNotNull(x509CertificateNew);
        assertEquals("CN=" + platform.getPlatformInstanceId(), x509CertificateNew.getSubjectDN().getName());
        assertNotEquals(x509Certificate, x509CertificateNew);

    }
}
