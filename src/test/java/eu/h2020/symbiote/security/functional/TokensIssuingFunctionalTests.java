package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.AbstractAAMAMQPTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
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
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class TokensIssuingFunctionalTests extends
        AbstractAAMAMQPTestSuite {

    private final String preferredPlatformId = "preferredPlatformId";
    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    @Value("${rabbit.queue.ownedservices.request}")
    protected String ownedServicesRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    String coreInterfaceAddress;

    @Autowired
    private PlatformRepository platformRepository;
    @Autowired
    private DummyPlatformAAM dummyPlatformAAM;


    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        savePlatformOwner();
        // platform registration useful
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserOverRESTWrongSignFailure() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, keyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        String homeToken = aamClient.getHomeToken(loginRequest);
        assertNotNull(homeToken);
    }

    @Test(expected = MalformedJWTException.class)
    public void getHomeTokenForUserOverRESTIncorrectTokenFormat() throws
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException {
        String homeToken = aamClient.getHomeToken("IncorrectlyFormattedToken");
        assertNotNull(homeToken);
    }

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserOverRESTWrongUsernameFailure() throws
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException {
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        aamClient.getHomeToken(loginRequest);
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserOverRESTWrongClientIdFailure() throws
            JWTCreationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException {
        HomeCredentials homeCredentials = new HomeCredentials(null, username, wrongClientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        aamClient.getHomeToken(loginRequest);
    }

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void getHomeTokenForUserOverRESTSuccessAndIssuesCoreTokenWithoutPOAttributes() throws
            IOException,
            MalformedJWTException,
            CertificateException,
            OperatorCreationException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            JWTCreationException,
            WrongCredentialsException,
            AAMException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = aamClient.getHomeToken(loginRequest);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(homeToken);
        // As the AAM is now configured as core we confirm that relevant token type was issued.
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        // verify that the token contains the user public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (username).getClientCertificates().entrySet().iterator().next().getValue().getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.getDecoder().decode(claimsFromToken.getSpk());

        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);
    }

    /**
     * Features: CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void getHomeTokenForPlatformOwnerOverRESTSuccessAndIssuesRelevantTokenTypeWithPOAttributes() throws
            IOException,
            MalformedJWTException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            JWTCreationException,
            WrongCredentialsException,
            AAMException,
            UnrecoverableKeyException {
        // verify that our platform is not in repository and that our platformOwner is in repository
        assertFalse(platformRepository.exists(preferredPlatformId));
        assertTrue(userRepository.exists(platformOwnerUsername));
        // issue platform registration
        User user = userRepository.findOne(platformOwnerUsername);
        X509Certificate certificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        String dummyPlatformAAMPEMCertString = CryptoHelper.convertX509ToPEM(certificate);
        user.getClientCertificates().put(platformId, new Certificate(dummyPlatformAAMPEMCertString));
        userRepository.save(user);

        HomeCredentials homeCredentials = new HomeCredentials(null, platformOwnerUsername, platformId, null, getPrivateKeyTestFromKeystore("keystores/platform_1.p12", "platform-1-1-c1"));
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        String homeToken = aamClient.getHomeToken(loginRequest);
        //verify that JWT was issued for user
        assertNotNull(homeToken);

        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(homeToken);
        //verify that JWT is of type Core as was released by a CoreAAM
        assertEquals(Token.Type.HOME, Token.Type.valueOf(claimsFromToken.getTtyp()));

        // verify that the token contains the platform owner public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (platformOwnerUsername).getClientCertificates().get(platformId).getX509()
                .getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.getDecoder().decode(claimsFromToken.getSpk());
        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);

    }

    /**
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */

    @Test(expected = ValidationException.class)
    public void getForeignTokenRequestOverRESTFailsForHomeTokenUsedAsRequest() throws
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            OperatorCreationException,
            NoSuchProviderException,
            JWTCreationException,
            ValidationException,
            MalformedJWTException,
            WrongCredentialsException,
            AAMException {
        addTestUserWithClientCertificateToRepository();
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String homeToken = aamClient.getHomeToken(loginRequest);
        aamClient.getForeignToken(homeToken, Optional.empty(), Optional.empty());
    }

    @Test
    public void getForeignTokenUsingPlatformTokenOverRESTSuccess() throws
            IOException,
            ValidationException,
            NoSuchProviderException,
            KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            MalformedJWTException,
            JWTCreationException,
            AAMException {
        // issuing dummy platform token
        String username = "userId";
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "platform-1";
        //inject platform with PEM Certificate to the database
        X509Certificate platformAAMCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        Platform dummyPlatform = new Platform(platformId, serverAddress + "/test", platformInstanceFriendlyName, userRepository.findOne(platformOwnerUsername), new Certificate(CryptoHelper.convertX509ToPEM(platformAAMCertificate)), new HashMap<>());
        platformRepository.save(dummyPlatform);
        String clientCertificate = CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1"));

        //checking token attributes
        JWTClaims claims = JWTEngine.getClaimsFromToken(dummyHomeToken.getToken());
        assertTrue(claims.getAtt().containsKey("name"));
        assertTrue(claims.getAtt().containsValue("test2"));
        // adding a federation
        List<FederationMember> platformsId = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId(platformId);
        platformsId.add(federationMember);

        Federation federation = new Federation();
        federation.setMembers(platformsId);
        federation.setId("federationId");

        federationsRepository.save(federation);

        // checking issuing of foreign token using the dummy platform token
        String token = aamClient.getForeignToken(
                dummyHomeToken.getToken(),
                Optional.of(clientCertificate),
                Optional.of(CryptoHelper.convertX509ToPEM(platformAAMCertificate)));
        // check if returned status is ok and if there is token in header
        assertNotNull(token);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token);
        assertEquals(Token.Type.FOREIGN, Token.Type.valueOf(claimsFromToken.getTtyp()));
        assertTrue(claimsFromToken.getAtt().containsKey("federation_1"));
        assertTrue(claimsFromToken.getAtt().containsValue("federationId"));
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenUsingPlatformTokenOverRESTFailPlatformNotRegistered() throws
            ValidationException,
            JWTCreationException,
            AAMException,
            MalformedJWTException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "platform-1";
        // adding a federation
        List<FederationMember> platformsId = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId(platformId);
        platformsId.add(federationMember);

        Federation federation = new Federation();
        federation.setMembers(platformsId);
        federation.setId("federationId");

        federationsRepository.save(federation);

        // checking issuing of foreign token using the dummy platform token
        aamClient.getForeignToken(dummyHomeToken.getToken(), Optional.empty(), Optional.empty());
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenUsingPlatformTokenOverRESTFailPlatformHasNotCertificate() throws
            ValidationException,
            JWTCreationException,
            AAMException,
            MalformedJWTException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));
        Platform dummyPlatform = new Platform(platformId, serverAddress + "/test", platformInstanceFriendlyName, userRepository.findOne(platformOwnerUsername), new Certificate(), new HashMap<>());
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

        // checking issuing of foreign token using the dummy platform token
        aamClient.getForeignToken(dummyHomeToken.getToken(), Optional.empty(), Optional.empty());
    }

    /**
     * Features: PAAM - 4, CAAM - 5 (tokens issueing)
     * Interfaces: PAAM - 5, CAAM - 11;
     * CommunicationType REST
     */

    @Test(expected = JWTCreationException.class)
    public void getForeignTokenFromCoreUsingPlatformTokenOverRESTFailsForUndefinedForeignMapping() throws
            IOException,
            ValidationException,
            CertificateException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            KeyStoreException,
            JWTCreationException,
            AAMException,
            MalformedJWTException {
        // issuing dummy platform token
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        String platformId = "platform-1";
        //inject platform with PEM Certificate to the database
        X509Certificate platformAAMCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        Platform dummyPlatform = new Platform(platformId, serverAddress + "/test", platformInstanceFriendlyName, userRepository.findOne(platformOwnerUsername), new Certificate(CryptoHelper.convertX509ToPEM(platformAAMCertificate)), new HashMap<>());
        platformRepository.save(dummyPlatform);
        // making sure the foreignMappingRules are empty
        federationsRepository.deleteAll();

        // checking issuing of foreign token using the dummy platform token
        aamClient.getForeignToken(dummyHomeToken.getToken(), Optional.empty(), Optional.empty());
    }

    @Test
    public void getGuestTokenOverRESTSuccess() throws
            JWTCreationException,
            AAMException,
            ValidationException {
        String acquired_token = aamClient.getGuestToken();
        assertNotNull(acquired_token);
        Token guestToken = new Token(acquired_token);
        String tokenTypeValue = guestToken.getClaims().get(SecurityConstants.CLAIM_NAME_TOKEN_TYPE, String.class);
        assertNotNull(tokenTypeValue);
        assertEquals(Token.Type.GUEST.toString(), tokenTypeValue);
    }
}
