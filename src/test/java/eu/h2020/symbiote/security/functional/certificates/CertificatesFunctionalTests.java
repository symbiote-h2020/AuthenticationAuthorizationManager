package eu.h2020.symbiote.security.functional.certificates;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import static io.jsonwebtoken.impl.crypto.RsaProvider.generateKeyPair;
import static org.junit.Assert.assertEquals;

@TestPropertySource("/core.properties")
public class CertificatesFunctionalTests extends
        AbstractAAMTestSuite {


    /**
     * Features: CAAM - 12 (AAM as a CA)
     * Interfaces: CAAM - 15;
     * CommunicationType REST
     */
    @Test
    public void getComponentCertificateOverRESTSuccess() throws NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException, KeyStoreException, IOException {
        ResponseEntity<String> response = restTemplate.getForEntity(serverAddress + SecurityConstants
                .AAM_GET_COMPONENT_CERTIFICATE, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(certificationAuthorityHelper.getAAMCert(), response.getBody());
    }

    @Test
    public void getClientCertificateOverRESTInvalidArguments() throws NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException, KeyStoreException, IOException, OperatorCreationException, SecurityHandlerException {
        KeyPair pair = generateKeyPair();
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal(certificationAuthorityHelper.getAAMCertificate().getSubjectX500Principal().getName()), pair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(pair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(usernameWithAt, password, clientId, csr);
        ResponseEntity<String> response = restTemplate.postForEntity(serverAddress + SecurityConstants.AAM_GET_CLIENT_CERTIFICATE,
                certRequest, String.class);
        assertEquals("Credentials contain illegal sign", response.getBody());
    }
}
