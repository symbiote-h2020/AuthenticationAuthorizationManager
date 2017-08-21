package eu.h2020.symbiote.security.functional;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.concurrent.TimeoutException;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class RevocationFunctionalTests extends
        AbstractAAMTestSuite {

    private final String recoveryMail = "null@dev.null";
    private final String platformId = "testPlatformId";
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    @Autowired
    private PlatformRepository platformRepository;
    private RpcClient revocationOverAMQPClient;

    @Bean
    DummyPlatformAAM getDummyPlatformAAM() {
        return new DummyPlatformAAM();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        // db cleanup
        platformRepository.deleteAll();
        userRepository.deleteAll();

        // platform registration useful
        revocationOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                revocationRequestQueue, 5000);
    }

    @Test
    public void revokeUserCertificateUsingCertificateOverRESTSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException, InvalidArgumentsException, WrongCredentialsException, NotExistingUserException, ValidationException {

        User user = new User();
        user.setUsername(username);
        user.setPasswordEncrypted(passwordEncoder.encode(password));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.USER);
        userRepository.save(user);

        AvailableAAMsCollection aamResponse = AAMClient.getAvailableAAMs();
        KeyPair pair = CryptoHelper.createKeyPair();
        AAM homeAAM = aamResponse.getAvailableAAMs().entrySet().iterator().next().getValue();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getCertificate().getX509(), username, clientId, pair);

        assertNotNull(csrString);

        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String clientCertificate = AAMClient.getClientCertificate(certRequest);

        assertNotNull(clientCertificate);
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(clientCertificate);

        assertTrue(Boolean.parseBoolean(AAMClient.revoke(revocationRequest)));


    }

    @Test
    public void revokePlatformCertificateUsingCertificateOverRESTSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException, InvalidArgumentsException, WrongCredentialsException, NotExistingUserException, ValidationException {

        User user = new User();
        user.setUsername(username);
        user.setPasswordEncrypted(passwordEncoder.encode(password));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(user);
        Platform platform = new Platform(platformId, null, null, user, null, new HashMap<String, Certificate>());
        platformRepository.save(platform);
        user.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(user);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);

        assertNotNull(csrString);

        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String platformCertificate = AAMClient.getClientCertificate(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(platformCertificate));
        platformRepository.save(platform);

        assertNotNull(platformCertificate);
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(platformCertificate);

        assertTrue(Boolean.parseBoolean(AAMClient.revoke(revocationRequest)));
    }

    @Test
    public void revokePlatformComponentCertificateUsingCertificateOverRESTSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException, InvalidArgumentsException, WrongCredentialsException, NotExistingUserException, ValidationException {

        User user = new User();
        user.setUsername(username);
        user.setPasswordEncrypted(passwordEncoder.encode(password));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(user);
        Platform platform = new Platform(platformId, null, null, user, null, new HashMap<String, Certificate>());
        platformRepository.save(platform);
        user.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(user);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);

        assertNotNull(csrString);

        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String componentCertificate = AAMClient.getClientCertificate(certRequest);
        platform.getComponentCertificates().put(componentId, new Certificate(componentCertificate));
        platformRepository.save(platform);

        assertNotNull(componentCertificate);
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(componentCertificate);

        assertTrue(Boolean.parseBoolean(AAMClient.revoke(revocationRequest)));
    }

    @Test
    public void revokeUserCertificateUsingCertificateOverAMQPSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException, InvalidArgumentsException, WrongCredentialsException, NotExistingUserException, ValidationException, TimeoutException {

        User user = new User();
        user.setUsername(username);
        user.setPasswordEncrypted(passwordEncoder.encode(password));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.USER);
        userRepository.save(user);

        AvailableAAMsCollection aamResponse = AAMClient.getAvailableAAMs();
        KeyPair pair = CryptoHelper.createKeyPair();
        AAM homeAAM = aamResponse.getAvailableAAMs().entrySet().iterator().next().getValue();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getCertificate().getX509(), username, clientId, pair);

        assertNotNull(csrString);

        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String clientCertificate = AAMClient.getClientCertificate(certRequest);

        assertNotNull(clientCertificate);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(clientCertificate);

        assertFalse(revokedKeysRepository.exists(username));
        byte[] response = revocationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (revocationRequest).getBytes());
        RevocationResponse revocationResponse = mapper.readValue(response,
                RevocationResponse.class);

        assertTrue(revocationResponse.isRevoked());
        assertEquals(HttpStatus.OK, revocationResponse.getStatus());
        assertTrue(revokedKeysRepository.exists(username));

    }

    @Test
    public void revokeUserCertificateUsingCommonNameOverRESTSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException, InvalidArgumentsException, WrongCredentialsException, NotExistingUserException, ValidationException {

        User user = new User();
        user.setUsername(username);
        user.setPasswordEncrypted(passwordEncoder.encode(password));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.USER);
        userRepository.save(user);

        AvailableAAMsCollection aamResponse = AAMClient.getAvailableAAMs();
        KeyPair pair = CryptoHelper.createKeyPair();
        AAM homeAAM = aamResponse.getAvailableAAMs().entrySet().iterator().next().getValue();
        String csrString = CryptoHelper.buildCertificateSigningRequestPEM(homeAAM.getCertificate().getX509(), username, clientId, pair);

        assertNotNull(csrString);

        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String clientCertificate = AAMClient.getClientCertificate(certRequest);

        assertNotNull(clientCertificate);
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        String commonName = username + illegalSign + clientId;
        revocationRequest.setCertificateCommonName(commonName);

        assertTrue(Boolean.parseBoolean(AAMClient.revoke(revocationRequest)));


    }

    @Test
    public void revokePlatformCertificateUsingCommonNameOverRESTSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException, InvalidArgumentsException, WrongCredentialsException, NotExistingUserException, ValidationException {

        User user = new User();
        user.setUsername(username);
        user.setPasswordEncrypted(passwordEncoder.encode(password));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(user);
        Platform platform = new Platform(platformId, null, null, user, null, new HashMap<String, Certificate>());
        platformRepository.save(platform);
        user.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(user);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildPlatformCertificateSigningRequestPEM(platformId, pair);

        assertNotNull(csrString);

        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String platformCertificate = AAMClient.getClientCertificate(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(platformCertificate));
        platformRepository.save(platform);

        assertNotNull(platformCertificate);
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        String commonName = platformId;
        revocationRequest.setCertificateCommonName(commonName);

        assertTrue(Boolean.parseBoolean(AAMClient.revoke(revocationRequest)));
    }

    @Test
    public void revokePlatformComponentCertificateUsingCommonNameOverRESTSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException, InvalidArgumentsException, WrongCredentialsException, NotExistingUserException, ValidationException {

        User user = new User();
        user.setUsername(username);
        user.setPasswordEncrypted(passwordEncoder.encode(password));
        user.setRecoveryMail(recoveryMail);
        user.setRole(UserRole.PLATFORM_OWNER);
        userRepository.save(user);
        Platform platform = new Platform(platformId, null, null, user, null, new HashMap<String, Certificate>());
        platformRepository.save(platform);
        user.getOwnedPlatforms().put(platformId, platform);
        userRepository.save(user);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildComponentCertificateSigningRequestPEM(componentId, platformId, pair);

        assertNotNull(csrString);

        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String componentCertificate = AAMClient.getClientCertificate(certRequest);
        platform.getComponentCertificates().put(componentId, new Certificate(componentCertificate));
        platformRepository.save(platform);

        assertNotNull(componentCertificate);
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        String commonName = componentId + illegalSign + platformId;
        revocationRequest.setCertificateCommonName(commonName);

        assertTrue(Boolean.parseBoolean(AAMClient.revoke(revocationRequest)));
    }

    @Test
    public void revokeHomeTokenOverRESTSuccess() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException, InvalidArgumentsException, WrongCredentialsException, NotExistingUserException, ValidationException, OperatorCreationException, InvalidKeyException, KeyStoreException, UnrecoverableKeyException, JWTCreationException, MalformedJWTException {

        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = AAMClient.getHomeToken(loginRequest);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(homeToken);
        // As the AAM is now configured as core we confirm that relevant token type was issued.
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setHomeTokenString(homeToken);

        assertTrue(Boolean.parseBoolean(AAMClient.revoke(revocationRequest)));
        assertTrue(revokedTokensRepository.exists(new Token(homeToken).getClaims().getId()));
    }

}