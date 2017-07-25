package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.interfaces.IGetToken;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;
import eu.h2020.symbiote.security.config.JerseyConfig;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import feign.Feign;
import feign.Logger;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import feign.jaxrs.JAXRSContract;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.assertEquals;

/**
 * Test suite for AAM with expired certificate
 *
 * @author Piotr Kicki (PSNC)
 */
@TestPropertySource("/coreExpired.properties")
public class AAMExpiredCertificateUnitTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(AAMExpiredCertificateUnitTests.class);
    @Value("${rabbit.queue.ownedplatformdetails.request}")
    protected String ownedPlatformDetailsRequestQueue;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface}")
    String platformAAMSuffixAtInterWorkingInterface;
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    @Autowired
    private ValidationHelper validationHelper;

    @LocalServerPort
    private int port;

    @Autowired
    private JerseyConfig jerseyConfig;

    @Override
    @Before
    public void setUp() throws Exception {
        serverAddress = "https://localhost:" + port + "/test/caam";//

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        // Test rest template
        restTemplate = new RestTemplate();

        // cleanup db
        userRepository.deleteAll();
        revokedKeysRepository.deleteAll();
        revokedTokensRepository.deleteAll();
        platformRepository.deleteAll();

        jerseyConfig.register(DummyCoreAAM.class);
        log.info("DummyCore is Registered: " + jerseyConfig.isRegistered(DummyCoreAAM.class));
    }

    @Test
    public void validateIssuerCertificateExpired() throws IOException, TimeoutException,
            NoSuchProviderException, KeyStoreException, CertificateException,
            NoSuchAlgorithmException, ValidationException, JWTCreationException {
        // issuing dummy core token from CoreAAM with expired certificate
        /*ResponseEntity<String> loginResponse = restTemplate.postForEntity(serverAddress +
                        SecurityConstants
                                .AAM_GET_HOME_TOKEN,
                new Credentials(username, password), String.class);    */

        IGetToken client = Feign.builder().logLevel(Logger.Level.FULL)
                .encoder(new JacksonEncoder()).decoder(new JacksonDecoder())
                .contract(new JAXRSContract()).target(IGetToken.class, serverAddress  );

        Response loginResponse = client.getHomeToken(new Credentials(username,password));

        Token dummyHomeToken = new Token(loginResponse
                .getHeaders().get(SecurityConstants.TOKEN_HEADER_NAME).get(0).toString());


        ValidationStatus response = validationHelper.validate(dummyHomeToken.getToken(), "");
        // check if platform token is not revoked
        assertEquals(ValidationStatus.EXPIRED_ISSUER_CERTIFICATE, response);
    }
}