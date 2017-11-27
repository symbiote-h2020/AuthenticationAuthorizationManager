package eu.h2020.symbiote.security.unit;

import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.FederationRule;
import eu.h2020.symbiote.security.communication.payloads.PlatformManagementRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.RevokedRemoteTokensRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import eu.h2020.symbiote.security.utils.DummyPlatformAAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.http.ResponseEntity;
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
import java.util.concurrent.TimeoutException;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;
import static eu.h2020.symbiote.security.services.helpers.TokenIssuer.buildAuthorizationToken;
import static org.junit.Assert.*;

@TestPropertySource("/cache.properties")
public class CacheTokensTests extends AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(CacheTokensTests.class);
    @Autowired
    protected RevokedRemoteTokensRepository revokedRemoteTokensRepository;
    @Autowired
    DummyPlatformAAM dummyPlatformAAM;
    @Autowired
    AAMServices aamServices;
    @Autowired
    private DummyCoreAAM dummyCoreAAM;
    @Autowired
    private ValidationHelper validationHelper;
    @Autowired
    private TokenIssuer tokenIssuer;
    @LocalServerPort
    private int port;
    private String dummyPlatformAAMPEMCertString;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        savePlatformOwner();
        // platform registration useful
        RpcClient platformRegistrationOverAMQPClient = new RpcClient(rabbitManager.getConnection().createChannel(), "",
                platformManagementRequestQueue, 5000);
        Credentials platformOwnerUserCredentials = new Credentials(platformOwnerUsername, platformOwnerPassword);
        // registering the platform to the Core AAM so it will be available
        String platformInstanceFriendlyName = "friendlyPlatformName";
        PlatformManagementRequest platformRegistrationOverAMQPRequest = new PlatformManagementRequest(
                new Credentials(AAMOwnerUsername, AAMOwnerPassword),
                platformOwnerUserCredentials,
                serverAddress + "/test",
                platformInstanceFriendlyName,
                "platform-1",
                OperationType.CREATE);
        platformRegistrationOverAMQPClient.primitiveCall(mapper.writeValueAsString
                (platformRegistrationOverAMQPRequest).getBytes());

        addTestUserWithClientCertificateToRepository();
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        dummyPlatformAAMPEMCertString = CryptoHelper.convertX509ToPEM(properAAMCert);
        Platform dummyPlatform = platformRepository.findOne("platform-1");
        //put platform certificate into database
        dummyPlatform.setPlatformAAMCertificate(new Certificate(dummyPlatformAAMPEMCertString));
        //put any valid certificate as client cert to pass validation
        dummyPlatform.getComponentCertificates().put(clientId, new Certificate(dummyPlatformAAMPEMCertString));
        platformRepository.save(dummyPlatform);
        dummyCoreAAM.port = port;


    }

    @Test
    public void validateForeignTokenOriginCredentialsValidAndCached() throws
            IOException,
            ValidationException,
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            JWTCreationException, TimeoutException, InterruptedException {

        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        // issuing dummy platform token
        ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress + "/test/paam" +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                loginRequest, String.class);
        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0));

        //set right interworkingInterfaceAddress to return VALID during any validation by this dummy platform
        Platform dummyPlatform = platformRepository.findOne("platform-1");
        assertNotNull(dummyPlatform);
        dummyPlatform.setPlatformInterworkingInterfaceAddress(serverAddress + "/test");
        platformRepository.save(dummyPlatform);
        //wait till cache ends
        Thread.sleep(availableAAMsCacheExpirationTime * 1000);

        FederationRule federationRule = new FederationRule("federationId", new HashSet<>());
        federationRule.addPlatform(dummyPlatform.getPlatformInstanceId());
        federationRule.addPlatform("testPlatform");
        federationRule.addPlatform("testPlatform2");
        federationRulesRepository.save(federationRule);

        Token foreignToken = null;
        try {
            foreignToken = tokenIssuer.getForeignToken(dummyHomeToken);
        } catch (Exception e) {
            log.error(e.getMessage(), e.getCause());
            fail("Exception thrown");
        }
        assertNotNull(foreignToken);

        //checking if foreign token is valid including client certificate - dummyplatformaam always confirms.
        assertEquals(ValidationStatus.VALID, validationHelper.validate(foreignToken.toString(), "", "", dummyPlatformAAMPEMCertString));
        //changing platforms address to make it return INVALID_TRUST_CHAIN during validation
        dummyPlatform.setPlatformInterworkingInterfaceAddress(serverAddress + "/test/failvalidation");
        platformRepository.save(dummyPlatform);
        //wait till cache ends
        Thread.sleep(availableAAMsCacheExpirationTime * 1000);
        // check, if token was properly cached (no checked by dummy platform)

        assertEquals(ValidationStatus.VALID, validationHelper.validate(foreignToken.toString(), "", "", ""));
        //wait for cleaning cache
        Thread.sleep(validTokenCacheExpirationTime);
        // check, if token was removed from cache
        assertEquals(ValidationStatus.INVALID_TRUST_CHAIN, validationHelper.validate(foreignToken.toString(), "", "", ""));
    }

    @Test
    public void validateRemoteTokenValidAndCached() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            UnrecoverableKeyException,
            ValidationException,
            TimeoutException, InterruptedException {


        X509Certificate userCertificate = getCertificateFromTestKeystore("platform_1.p12", "userid@clientid@platform-1");
        X509Certificate properAAMCert = getCertificateFromTestKeystore("platform_1.p12", "platform-1-1-c1");
        log.info("proper AAM: " + properAAMCert.getSubjectDN());
        log.info("proper AAM sign: " + properAAMCert.getIssuerDN());
        // registering the platform to the Core AAM so it will be available for token revocation

        Platform dummyPlatform = platformRepository.findOne("platform-1");
        assertNotNull(dummyPlatform);
        dummyPlatform.setPlatformInterworkingInterfaceAddress(serverAddress + "/test");
        platformRepository.save(dummyPlatform);

        Thread.sleep(availableAAMsCacheExpirationTime * 1000);

        String testHomeToken = buildAuthorizationToken(
                "userId@clientId",
                new HashMap<>(),
                userCertificate.getPublicKey().getEncoded(),
                Token.Type.HOME,
                100000l,
                "platform-1",
                properAAMCert.getPublicKey(),
                getPrivateKeyFromKeystore("platform_1.p12", "platform-1-1-c1")
        );
        Token homeToken = new Token(testHomeToken);
        assertFalse(revokedTokensRepository.exists(homeToken.getId()));
        // valid remote home token chain, token will be cached
        assertEquals(
                ValidationStatus.VALID,
                validationHelper.validate(
                        testHomeToken,
                        "",
                        "",
                        "")
        );
        // set dummy platform, which returns ValidationStatus.INVALID_TRUST_CHAIN
        dummyPlatform.setPlatformInterworkingInterfaceAddress(serverAddress + "/test/failvalidation");
        platformRepository.save(dummyPlatform);
        assertFalse(revokedRemoteTokensRepository.exists(homeToken.getClaims().getIssuer() + illegalSign + homeToken.getId()));
        // check, if token was properly cached (no checked by dummy platform)
        Thread.sleep(availableAAMsCacheExpirationTime * 1000);
        assertEquals(
                ValidationStatus.VALID,
                validationHelper.validate(
                        testHomeToken,
                        "",
                        "",
                        "")
        );
        Thread.sleep(validTokenCacheExpirationTime);
        // check, if token was removed from cache
        assertEquals(
                ValidationStatus.INVALID_TRUST_CHAIN,
                validationHelper.validate(
                        testHomeToken,
                        "",
                        "",
                        "")
        );


    }
}
