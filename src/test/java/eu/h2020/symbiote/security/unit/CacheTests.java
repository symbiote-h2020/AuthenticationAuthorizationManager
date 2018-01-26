package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.FederationRule;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;

import static eu.h2020.symbiote.security.services.helpers.TokenIssuer.buildAuthorizationToken;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.times;

@TestPropertySource("/cache.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public class CacheTests extends AbstractAAMTestSuite {

    @SpyBean
    private AAMServices aamServices;
    @SpyBean
    private DummyPlatformAAM dummyPlatformAAM;

    @Autowired
    private ValidationHelper validationHelper;
    @Autowired
    private TokenIssuer tokenIssuer;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        // to make sure caches are reset
        Thread.sleep(1100);
        User platformOwner = savePlatformOwner();
        addTestUserWithClientCertificateToRepository();
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        Platform dummyPlatform = new Platform(
                "platform-1",
                serverAddress + "/test",
                "friendlyPlatformName",
                platformOwner,
                new Certificate(CryptoHelper.convertX509ToPEM(properAAMCert)),
                new HashMap<>());
        platformRepository.save(dummyPlatform);
    }

    @Test
    public void verifyThatValidationHelperUsesCachedValidResultsForForeignTokenOriginTokens() throws
            ValidationException,
            JWTCreationException,
            MalformedJWTException,
            IOException,
            ClassNotFoundException {

        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        // issuing dummy platform token
        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        // defining federation
        Platform dummyPlatform = platformRepository.findOne("platform-1");
        FederationRule federationRule = new FederationRule("federationId", new HashSet<>());
        federationRule.addPlatform(dummyPlatform.getPlatformInstanceId());
        federationRule.addPlatform(SecurityConstants.CORE_AAM_INSTANCE_ID);
        federationRulesRepository.save(federationRule);

        Token foreignToken = tokenIssuer.getForeignToken(dummyHomeToken);

        assertEquals(ValidationStatus.VALID, validationHelper.validate(foreignToken.toString(), "", "", ""));
        assertEquals(ValidationStatus.VALID, validationHelper.validate(foreignToken.toString(), "", "", ""));
        Mockito.verify(dummyPlatformAAM, times(1)).validateForeignTokenOriginCredentials(foreignToken.getToken());
    }

    @Test
    public void verifyThatValidationHelperUsesCachedValidResultsForRemotelyIssuedToken() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            UnrecoverableKeyException {


        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyTestFromKeystore("platform_1.p12", "platform-1-1-c1")
        );

        // valid remote home token chain, token will be cached
        assertEquals(ValidationStatus.VALID, validationHelper.validate(testHomeToken, "", "", ""));
        assertEquals(ValidationStatus.VALID, validationHelper.validate(testHomeToken, "", "", ""));
        Mockito.verify(dummyPlatformAAM, times(1)).validate(testHomeToken);
    }


    @Test
    public void getComponentCertificateCached() throws
            CertificateException,
            AAMException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            InvalidArgumentsException,
            IOException {

        aamServices.getComponentCertificate(componentId, "platform-1");
        aamServices.getComponentCertificate(componentId, "platform-1");
        Mockito.verify(dummyPlatformAAM, times(1)).getComponentCertificate(Mockito.anyString(), Mockito.anyString());
        aamServices.deleteFromCacheComponentCertificate(componentId, "platform-1");
        aamServices.getComponentCertificate(componentId, "platform-1");
        Mockito.verify(dummyPlatformAAM, times(2)).getComponentCertificate(Mockito.anyString(), Mockito.anyString());
    }

    @Test
    public void getAvailableAAMsCached() throws
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException {

        aamServices.getAvailableAAMs();
        aamServices.getAvailableAAMs();
        Mockito.verify(aamServices, times(1)).getAvailableAAMs();
        aamServices.deleteFromCacheAvailableAAMs();
        aamServices.getAvailableAAMs();
        Mockito.verify(aamServices, times(2)).getAvailableAAMs();
    }

    @Test
    public void getAAMsInternallyCached() throws
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException {

        aamServices.getAAMsInternally();
        aamServices.getAAMsInternally();
        Mockito.verify(aamServices, times(1)).getAAMsInternally();
        aamServices.deleteFromCacheInternalAAMs();
        aamServices.getAAMsInternally();
        Mockito.verify(aamServices, times(2)).getAAMsInternally();
    }
}
