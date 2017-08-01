package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import feign.Response;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;

import static org.junit.Assert.assertEquals;

@TestPropertySource("/core.properties")
public class ClientCertificatesIssuingFunctionalTests extends
        AbstractAAMTestSuite {
    @Test
    public void getClientCertificateOverRESTInvalidArguments() throws NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException, KeyStoreException, IOException, OperatorCreationException, SecurityHandlerException, InvalidAlgorithmParameterException {
        KeyPair pair = CryptoHelper.createKeyPair();
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal(certificationAuthorityHelper.getAAMCertificate().getSubjectX500Principal().getName()), pair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM);
        ContentSigner signer = csBuilder.build(pair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        CertificateRequest certRequest = new CertificateRequest(usernameWithAt, password, clientId, Base64.getEncoder().encodeToString(csr.getEncoded()));
        Response response = restInterfce.getClientCertificate(certRequest);
        assertEquals("Credentials contain illegal sign", response.body().toString());
    }

    // TODO where are other tests?
}
