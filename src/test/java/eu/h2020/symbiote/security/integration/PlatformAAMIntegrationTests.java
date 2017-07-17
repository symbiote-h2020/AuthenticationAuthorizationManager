package eu.h2020.symbiote.security.integration;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.handler.InternalSecurityHandler;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeoutException;

import static org.junit.Assert.*;

/**
 * Test suite for Platform side AAM deployment scenarios.
 */
@TestPropertySource("/platform.properties")
public class PlatformAAMIntegrationTests extends
        AbstractAAMTestSuite {

    private static Log log = LogFactory.getLog(PlatformAAMIntegrationTests.class);

    @Value("${rabbit.host}")
    protected String rabbitHost;
    @Value("${rabbit.username}")
    protected String rabbitUsername;
    @Value("${rabbit.password}")
    protected String rabbitPassword;


    /**
     * Feature: 3 (Authentication of components/ and users registered in a platform)
     * Interface: PAAM - 1 and CAAM (for Administration)
     * CommunicationType AMQP
     *
     * @throws IOException
     * @throws TimeoutException
     */
    @Test
    @Ignore("We need to think how to initiate to local AAMs (a core and a platform one")
    public void userLoginOverAMQPSuccessAndIssuesCoreTokenType()
            throws IOException, TimeoutException, SecurityHandlerException, MalformedJWTException, CertificateException {

        InternalSecurityHandler securityHandler =
                new InternalSecurityHandler(serverAddress, rabbitHost, rabbitUsername, rabbitPassword);
        Token token = securityHandler.requestFederatedCoreToken(username, password);
        assertNotNull(token.getToken());

        log.info("Test Client received this Token: " + token.toString());

        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
        assertEquals(IssuingAuthorityType.PLATFORM, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

        // verify that the token contains the user public key
        byte[] userPublicKeyInRepository = userRepository.findOne
                (username).getCertificate().getX509().getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.decodeBase64(claimsFromToken.getSpk());
        assertArrayEquals(userPublicKeyInRepository, publicKeyFromToken);
    }
}