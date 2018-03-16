package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.AbstractAAMAMQPTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.CredentialsValidationService;
import eu.h2020.symbiote.security.services.GetTokenService;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.junit.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.FIELDS_DELIMITER;
import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class RevocationFunctionalTests extends
        AbstractAAMAMQPTestSuite {

    @Autowired
    DummyPlatformAAM dummyPlatformAAM;
    @Autowired
    private PlatformRepository platformRepository;
    @Autowired
    private GetTokenService getTokenService;
    @Value("${aam.deployment.owner.username}")
    private String AAMOwnerUsername;
    @Value("${aam.deployment.owner.password}")
    private String AAMOwnerPassword;

    @Autowired
    private CredentialsValidationService credentialsValidationService;
    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Test
    public void revokeUserCertificateUsingCertificateOverRESTSuccess() throws
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

        assertNotNull(clientCertificate);
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(clientCertificate);

        assertTrue(Boolean.parseBoolean(aamClient.revokeCredentials(revocationRequest)));


    }

    @Test
    public void revokePlatformCertificateUsingCertificateOverRESTSuccess() throws
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

        User user = createUser(username, password, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(user);
        Platform platform = new Platform(platformId,
                null,
                null,
                user,
                new Certificate(),
                new HashMap<>());
        platformRepository.save(platform);
        user.getOwnedServices().add(platformId);
        userRepository.save(user);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platformId, pair);

        assertNotNull(csrString);

        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String platformCertificate = aamClient.signCertificateRequest(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(platformCertificate));
        platformRepository.save(platform);

        assertNotNull(platformCertificate);
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(platformCertificate);

        assertTrue(Boolean.parseBoolean(aamClient.revokeCredentials(revocationRequest)));
    }

    @Test
    public void revokeSmartSpaceCertificateUsingCertificateOverRESTSuccess() throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            IOException,
            InvalidArgumentsException,
            WrongCredentialsException,
            AAMException,
            InvalidAlgorithmParameterException,
            NotExistingUserException,
            ValidationException {

        User user = createUser(username, password, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(user);
        // issue smartSpace registration
        SmartSpace smartSpace = new SmartSpace(preferredSmartSpaceId, smartSpaceInstanceFriendlyName, smartSpaceGateWayAddress, isExposingSiteLocalAddress, smartSpaceSiteLocalAddress, new Certificate(), new HashMap<>(), user);
        smartSpaceRepository.save(smartSpace);
        user.getOwnedServices().add(preferredSmartSpaceId);
        userRepository.save(user);
        // inject service AAM Cert
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(preferredSmartSpaceId, pair);

        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String smartSpaceCertificate = aamClient.signCertificateRequest(certRequest);
        smartSpace.setLocalCertificationAuthorityCertificate(new Certificate(smartSpaceCertificate));
        // save the certs into the repo
        smartSpaceRepository.save(smartSpace);

        user.getOwnedServices().add(preferredSmartSpaceId);
        userRepository.save(user);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(smartSpaceCertificate);

        assertTrue(Boolean.parseBoolean(aamClient.revokeCredentials(revocationRequest)));
    }


    @Test
    public void revokeUserCertificateUsingCertificateOverAMQPSuccess() throws
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

        assertNotNull(clientCertificate);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificatePEMString(clientCertificate);

        assertFalse(revokedKeysRepository.exists(username));
        byte[] response = rabbitTemplate.sendAndReceive(revocationRequestQueue, new Message(mapper.writeValueAsBytes
                (revocationRequest), new MessageProperties())).getBody();
        RevocationResponse revocationResponse = mapper.readValue(response,
                RevocationResponse.class);

        assertTrue(revocationResponse.isRevoked());
        assertEquals(HttpStatus.OK, revocationResponse.getStatus());
        assertTrue(revokedKeysRepository.exists(username));

    }

    @Test
    public void revokeUserCertificateUsingCommonNameOverRESTSuccess() throws
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

        assertNotNull(clientCertificate);
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        String commonName = username + FIELDS_DELIMITER + clientId;
        revocationRequest.setCertificateCommonName(commonName);

        assertTrue(Boolean.parseBoolean(aamClient.revokeCredentials(revocationRequest)));


    }

    @Test
    public void revokePlatformCertificateUsingCommonNameOverRESTSuccess() throws
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

        User user = createUser(username, password, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(user);
        Platform platform = new Platform(
                platformId,
                null,
                null,
                user,
                new Certificate(),
                new HashMap<>());
        platformRepository.save(platform);
        user.getOwnedServices().add(platformId);
        userRepository.save(user);

        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(platformId, pair);

        assertNotNull(csrString);

        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String platformCertificate = aamClient.signCertificateRequest(certRequest);
        platform.setPlatformAAMCertificate(new Certificate(platformCertificate));
        platformRepository.save(platform);

        assertNotNull(platformCertificate);
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificateCommonName(platformId);

        assertTrue(Boolean.parseBoolean(aamClient.revokeCredentials(revocationRequest)));
    }

    @Test
    public void revokeSmartSpaceCertificateUsingCommonNameOverRESTSuccess() throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            CertificateException,
            IOException,
            InvalidArgumentsException,
            WrongCredentialsException,
            AAMException,
            InvalidAlgorithmParameterException, NotExistingUserException, ValidationException {

        User user = createUser(username, password, recoveryMail, UserRole.SERVICE_OWNER);
        userRepository.save(user);
        // issue smartSpace registration
        SmartSpace smartSpace = new SmartSpace(preferredSmartSpaceId, smartSpaceInstanceFriendlyName, smartSpaceGateWayAddress, isExposingSiteLocalAddress, smartSpaceSiteLocalAddress, new Certificate(), new HashMap<>(), user);
        smartSpaceRepository.save(smartSpace);
        user.getOwnedServices().add(preferredSmartSpaceId);
        userRepository.save(user);
        // inject smartSpace AAM Cert
        KeyPair pair = CryptoHelper.createKeyPair();
        String csrString = CryptoHelper.buildServiceCertificateSigningRequestPEM(preferredSmartSpaceId, pair);

        assertNotNull(csrString);
        CertificateRequest certRequest = new CertificateRequest(username, password, clientId, csrString);
        String smartSpaceCertificate = aamClient.signCertificateRequest(certRequest);
        smartSpace.setLocalCertificationAuthorityCertificate(new Certificate(smartSpaceCertificate));
        // save the certs into the repo
        smartSpaceRepository.save(smartSpace);

        user.getOwnedServices().add(preferredSmartSpaceId);
        userRepository.save(user);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setCertificateCommonName(preferredSmartSpaceId);

        assertTrue(Boolean.parseBoolean(aamClient.revokeCredentials(revocationRequest)));
    }

    @Test
    public void revokeHomeTokenOverRESTSuccess() throws
            InvalidArgumentsException,
            WrongCredentialsException,
            ValidationException,
            JWTCreationException,
            MalformedJWTException,
            AAMException {

        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = aamClient.getHomeToken(loginRequest);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(homeToken);
        // As the AAM is now configured as core we confirm that relevant token type was issued.
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(username, password));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        revocationRequest.setHomeTokenString(homeToken);

        assertTrue(Boolean.parseBoolean(aamClient.revokeCredentials(revocationRequest)));
        assertTrue(revokedTokensRepository.exists(new Token(homeToken).getClaims().getId()));
    }

    @Test
    public void revokeForeignTokenOverRESTSuccess() throws
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            JWTCreationException,
            ValidationException,
            InvalidArgumentsException,
            WrongCredentialsException,
            MalformedJWTException,
            AAMException {
        addTestUserWithClientCertificateToRepository();
        assertNotNull(userRepository.findOne(username));
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        Token token = new Token(dummyPlatformAAM.getHomeToken(loginRequest).getHeaders().getFirst(SecurityConstants.TOKEN_HEADER_NAME));
        assertNotNull(token);
        User platformOwner = savePlatformOwner();

        String platformId = "platform-1";
        Platform platform = new Platform(
                platformId,
                serverAddress + "/test",
                null,
                platformOwner,
                new Certificate(),
                new HashMap<>());
        platformRepository.save(platform);
        platformOwner.getOwnedServices().add(platformId);
        userRepository.save(platformOwner);

        //inject platform PEM Certificate to the database
        Platform dummyPlatform = platformRepository.findOne(platformId);
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAM.getRootCertificate()));
        platformRepository.save(dummyPlatform);

        // adding a federation
        List<FederationMember> platformsId = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId(platformId);
        platformsId.add(federationMember);

        Federation federation = new Federation();
        federation.setMembers(platformsId);
        federation.setId("federationId");

        federationsRepository.save(federation);

        Token foreignToken = getTokenService.getForeignToken(token, "", "");
        assertNotNull(foreignToken);

        RevocationRequest revocationRequest = new RevocationRequest();

        revocationRequest.setHomeTokenString(token.toString());
        revocationRequest.setForeignTokenString(foreignToken.toString());

        assertTrue(Boolean.parseBoolean(aamClient.revokeCredentials(revocationRequest)));
        assertTrue(revokedTokensRepository.exists(foreignToken.getClaims().getId()));
        assertEquals(ValidationStatus.REVOKED_TOKEN, credentialsValidationService.validate(foreignToken.getToken(), "", "", ""));
    }

    @Test(expected = InvalidArgumentsException.class)
    public void revokeForeignTokenOverRESTFailNoTokens() throws
            WrongCredentialsException,
            InvalidArgumentsException,
            AAMException {
        RevocationRequest revocationRequest = new RevocationRequest();
        aamClient.revokeCredentials(revocationRequest);
    }

    @Test
    public void revokeUserCertificateUsingCertificateOverAMQPByAdminSuccess() throws
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

        assertNotNull(clientCertificate);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCertificatePEMString(clientCertificate);

        assertFalse(revokedKeysRepository.exists(username));
        byte[] response = rabbitTemplate.sendAndReceive(revocationRequestQueue, new Message(mapper.writeValueAsBytes
                (revocationRequest), new MessageProperties())).getBody();
        RevocationResponse revocationResponse = mapper.readValue(response,
                RevocationResponse.class);

        assertTrue(revocationResponse.isRevoked());
        assertEquals(HttpStatus.OK, revocationResponse.getStatus());
        assertTrue(revokedKeysRepository.exists(username));
    }

    @Test
    public void revokeHomeTokenOverAMQPByAdminSuccess() throws
            IOException,
            WrongCredentialsException,
            ValidationException,
            JWTCreationException,
            MalformedJWTException,
            AAMException {

        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = aamClient.getHomeToken(loginRequest);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(homeToken);
        // As the AAM is now configured as core we confirm that relevant token type was issued.
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setHomeTokenString(homeToken);

        assertFalse(revokedTokensRepository.exists(new Token(homeToken).getId()));
        byte[] response = rabbitTemplate.sendAndReceive(revocationRequestQueue, new Message(mapper.writeValueAsBytes
                (revocationRequest), new MessageProperties())).getBody();
        RevocationResponse revocationResponse = mapper.readValue(response,
                RevocationResponse.class);

        assertTrue(revocationResponse.isRevoked());
        assertEquals(HttpStatus.OK, revocationResponse.getStatus());
        assertTrue(revokedTokensRepository.exists(new Token(homeToken).getId()));
    }

    @Test
    public void revokeOverAMQPByAdminFailEmptyRequestOrBadAdminCredentials() throws
            IOException {

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);

        byte[] response = rabbitTemplate.sendAndReceive(revocationRequestQueue, new Message(mapper.writeValueAsBytes
                (revocationRequest), new MessageProperties())).getBody();
        RevocationResponse revocationResponse = mapper.readValue(response,
                RevocationResponse.class);

        assertFalse(revocationResponse.isRevoked());
        assertEquals(HttpStatus.BAD_REQUEST, revocationResponse.getStatus());

        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, password));
        response = rabbitTemplate.sendAndReceive(revocationRequestQueue, new Message(mapper.writeValueAsBytes
                (revocationRequest), new MessageProperties())).getBody();
        revocationResponse = mapper.readValue(response,
                RevocationResponse.class);

        assertFalse(revocationResponse.isRevoked());
        assertEquals(HttpStatus.BAD_REQUEST, revocationResponse.getStatus());

    }

    @Test
    public void sendMessageOverAMQPFailWrongMessage() throws
            IOException {
        String wrongmessage = "{wrong message json}";
        // send incorrect message over AMQP
        byte[] response = rabbitTemplate.sendAndReceive(revocationRequestQueue, new Message(mapper.writeValueAsBytes
                (wrongmessage), new MessageProperties())).getBody();
        ErrorResponseContainer sspRegistrationOverAMQPResponse = mapper.readValue(response,
                ErrorResponseContainer.class);
        assertEquals(HttpStatus.BAD_REQUEST.value(), sspRegistrationOverAMQPResponse.getErrorCode());
    }
}