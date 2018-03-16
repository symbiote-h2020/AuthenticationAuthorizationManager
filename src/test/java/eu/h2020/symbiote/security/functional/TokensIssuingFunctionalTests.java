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
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class TokensIssuingFunctionalTests extends
        AbstractAAMAMQPTestSuite {

    private final String platformInstanceFriendlyName = "friendlyPlatformName";
    @Autowired
    private PlatformRepository platformRepository;
    @Autowired
    private DummyPlatformAAM dummyPlatformAAM;

    @Test
    public void getHomeTokenForUserOverRESTSuccess() throws
            MalformedJWTException,
            CertificateException,
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

    @Test(expected = WrongCredentialsException.class)
    public void getHomeTokenForUserOverRESTFailNotRegisteredUser() throws
            MalformedJWTException,
            JWTCreationException,
            WrongCredentialsException,
            AAMException {
        // no user in repo
        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        aamClient.getHomeToken(loginRequest);
    }

    @Test(expected = ValidationException.class)
    public void getForeignTokenUsingGuestTokenOverRESTFail() throws
            ValidationException,
            JWTCreationException,
            AAMException {
        // issuing guest token
        String acquired_token = aamClient.getGuestToken();
        assertNotNull(acquired_token);

        // checking issuing of foreign token using the dummy platform token
        aamClient.getForeignToken(
                acquired_token,
                Optional.empty(),
                Optional.empty());

    }

    @Test
    public void getForeignTokenUsingPlatformHomeTokenOverRESTSuccess() throws
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
