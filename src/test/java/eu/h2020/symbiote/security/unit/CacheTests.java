package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static eu.h2020.symbiote.security.services.helpers.TokenIssuer.buildAuthorizationToken;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.times;

@TestPropertySource("/core_cache.properties")
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
    private String platformId = "platform-1";

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        //clear caches
        aamServices.invalidateAvailableAAMsCache();
        aamServices.invalidateInternalAAMsCache();
        aamServices.invalidateComponentCertificateCache(componentId, platformId);

        User platformOwner = savePlatformOwner();
        addTestUserWithClientCertificateToRepository();
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");
        Platform dummyPlatform = new Platform(
                platformId,
                serverAddress + "/test",
                platformInstanceFriendlyName,
                platformOwner,
                new Certificate(CryptoHelper.convertX509ToPEM(properAAMCert)),
                new HashMap<>());
        platformRepository.save(dummyPlatform);
        dummyPlatformAAM.certificateFlag = 1;
    }

    @Test
    public void verifyThatValidationHelperUsesCachedValidResultsForForeignTokenOriginTokens() throws
            ValidationException,
            JWTCreationException,
            MalformedJWTException {

        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        // issuing dummy platform token
        ResponseEntity<?> loginResponse = dummyPlatformAAM.getHomeToken(loginRequest);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        Platform dummyPlatform = platformRepository.findOne(platformId);
        // adding a federation
        List<FederationMember> platformsId = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId(dummyPlatform.getPlatformInstanceId());
        platformsId.add(federationMember);
        federationMember = new FederationMember();
        federationMember.setPlatformId(SecurityConstants.CORE_AAM_INSTANCE_ID);
        platformsId.add(federationMember);
        Federation federation = new Federation();
        federation.setMembers(platformsId);
        federation.setId("federationId");

        federationsRepository.save(federation);
        //acquire foreign token
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


        X509Certificate userCertificate = getCertificateFromTestKeystore("keystores/platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("keystores/platform_1.p12", "platform-1-1-c1");

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                platformId,
                properAAMCert.getPublicKey(),
                getPrivateKeyTestFromKeystore("keystores/platform_1.p12", "platform-1-1-c1")
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

        //dirty hack to pass TrustChain of the certificate. (client cert is returned)
        dummyPlatformAAM.certificateFlag = 2;
        aamServices.getComponentCertificate(componentId, platformId);
        aamServices.getComponentCertificate(componentId, platformId);
        Mockito.verify(dummyPlatformAAM, times(1)).getComponentCertificate(Mockito.anyString(), Mockito.anyString());
        aamServices.invalidateComponentCertificateCache(componentId, platformId);
        aamServices.getComponentCertificate(componentId, platformId);
        Mockito.verify(dummyPlatformAAM, times(2)).getComponentCertificate(Mockito.anyString(), Mockito.anyString());
    }

    @Test
    public void getAvailableAAMsCached() throws
            CertificateException,
            IOException {

        aamServices.getAvailableAAMs();
        aamServices.getAvailableAAMs();
        Mockito.verify(aamServices, times(1)).getAvailableAAMs();
        aamServices.invalidateAvailableAAMsCache();
        aamServices.getAvailableAAMs();
        Mockito.verify(aamServices, times(2)).getAvailableAAMs();
    }

    @Test
    public void getAAMsInternallyCached() throws
            CertificateException,
            IOException {

        aamServices.getAAMsInternally();
        aamServices.getAAMsInternally();
        Mockito.verify(aamServices, times(1)).getAAMsInternally();
        aamServices.invalidateInternalAAMsCache();
        aamServices.getAAMsInternally();
        Mockito.verify(aamServices, times(2)).getAAMsInternally();
    }
}
