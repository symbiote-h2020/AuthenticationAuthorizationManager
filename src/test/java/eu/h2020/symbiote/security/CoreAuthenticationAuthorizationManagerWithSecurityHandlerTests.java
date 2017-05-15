package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.enums.CoreAttributes;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.UserRole;
import eu.h2020.symbiote.security.exceptions.aam.MalformedJWTException;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Test suite for generic AAM functionality irrelevant to actual deployment type (Core or Platform)
 */
@TestPropertySource("/core.properties")
public class CoreAuthenticationAuthorizationManagerWithSecurityHandlerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CoreAuthenticationAuthorizationManagerWithSecurityHandlerTests.class);

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }


    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    public void externalLoginUsingSecurityHandlerSuccess() throws MalformedJWTException, IOException,
            CertificateException {

        SecurityHandler securityHandler = new SecurityHandler(serverAddress);
        Token token = securityHandler.requestCoreToken(username, password);

        JWTClaims claimsFromToken;
        claimsFromToken = JWTEngine.getClaimsFromToken(token.getToken());
        // As the AAM is now configured as core we confirm that relevant token type was issued.
        assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

        // verify that this JWT contains attributes relevant for application role
        Map<String, String> attributes = claimsFromToken.getAtt();
        assertEquals(UserRole.APPLICATION.toString(), attributes.get(CoreAttributes.ROLE.toString()));

        // verify that the token contains the platform owner public key
        byte[] applicationPublicKeyInRepository = userRepository.findOne
                (username).getCertificate().getX509().getPublicKey().getEncoded();
        byte[] publicKeyFromToken = Base64.decodeBase64(claimsFromToken.getSpk());
        assertArrayEquals(applicationPublicKeyInRepository, publicKeyFromToken);
    }
}