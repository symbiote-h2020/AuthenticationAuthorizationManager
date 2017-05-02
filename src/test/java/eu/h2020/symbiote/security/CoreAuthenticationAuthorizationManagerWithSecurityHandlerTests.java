package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.MalformedJWTException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.commons.jwt.attributes.CoreAttributes;
import eu.h2020.symbiote.security.exception.DisabledException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Test suite for generic AAM functionality irrelevant to actual deployment type (Core or Platform)
 */
@TestPropertySource("/core.properties")
public class CoreAuthenticationAuthorizationManagerWithSecurityHandlerTests extends
        AuthenticationAuthorizationManagerTests {

    private static Log log = LogFactory.getLog(CoreAuthenticationAuthorizationManagerWithSecurityHandlerTests.class);

    /**
     * Features: PAAM - 3, CAAM - 5 (Authentication & relevent token issuing)
     * Interfaces: PAAM - 3, CAAM - 7;
     * CommunicationType REST
     */
    @Test
    @Ignore("WIP")
    public void externalLoginUsingSecurityHandlerSuccess() throws DisabledException {
        SecurityHandler securityHandler = new SecurityHandler("http://localhost:8080/", "127.0.0.1",true);
        securityHandler.appRequestCoreToken(username,password);

        // TODO continue
        /*
        try {
            JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(headers.getFirst(tokenHeaderName));
            // As the AAM is now configured as core we confirm that relevant token type was issued.
            assertEquals(IssuingAuthorityType.CORE, IssuingAuthorityType.valueOf(claimsFromToken.getTtyp()));

            // verify that this JWT contains attributes relevant for application role
            Map<String, String> attributes = claimsFromToken.getAtt();
            assertEquals(UserRole.APPLICATION.toString(), attributes.get(CoreAttributes.ROLE.toString()));

            // verify that the token contains the application public key
            byte[] applicationPublicKeyInRepository = registrationManager.convertPEMToX509(userRepository.findOne(username).getCertificate().getPemCertificate()).getPublicKey().getEncoded();
            byte[] publicKeyFromToken = claimsFromToken.getSpk().getBytes();
            assertEquals(applicationPublicKeyInRepository,publicKeyFromToken);

        } catch (MalformedJWTException | JSONException | CertificateException | IOException e) {
            e.printStackTrace();
        }
        */
    }
}