package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Certificate related set of functions.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
@Component
public class CertificationAuthorityHelper {
    private static Log log = LogFactory.getLog(CertificationAuthorityHelper.class);
    private static final Long certificateValidityPeriod = 1L * 365L * 24L * 60L * 60L * 1000L;

    @Value("${aam.security.KEY_STORE_FILE_NAME}")
    private String KEY_STORE_FILE_NAME;
    @Value("${aam.security.ROOT_CA_CERTIFICATE_ALIAS}")
    private String ROOT_CA_CERTIFICATE_ALIAS;
    @Value("${aam.security.CERTIFICATE_ALIAS}")
    private String CERTIFICATE_ALIAS;

    @Value("${aam.security.KEY_STORE_PASSWORD}")
    private String KEY_STORE_PASSWORD;
    @Value("${aam.security.PV_KEY_PASSWORD}")
    private String PV_KEY_PASSWORD;

    public CertificationAuthorityHelper() throws CertificateException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * @return resolves the deployment type using the AAM certificate
     */
    public IssuingAuthorityType getDeploymentType() {
        String aamInstanceIdentifier = getAAMInstanceIdentifier();
        if (aamInstanceIdentifier.isEmpty())
            return IssuingAuthorityType.NULL;
        if (aamInstanceIdentifier.equals(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID))
            return IssuingAuthorityType.CORE;
        return IssuingAuthorityType.PLATFORM;
    }

    /**
     * @return resolves the aam instance identifier using the AAM certificate
     */
    public String getAAMInstanceIdentifier() {
        try {
            return getAAMCertificate().getSubjectX500Principal().getName().split("CN=")[1].split(",")[0];
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | IOException |
                CertificateException e) {
            log.error(e);
            return "";
        }
    }


    /**
     * @return Retrieves AAM's certificate in PEM format
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public String getAAMCert() throws NoSuchProviderException, KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException {
        return CryptoHelper.convertX509ToPEM(getAAMCertificate());
    }

    /**
     * @return Retrieves RootCA's certificate in PEM format
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public String getRootCACert() throws NoSuchProviderException, KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException {
        return CryptoHelper.convertX509ToPEM(getAAMCertificate());
    }

    /**
     * @return RootCA certificate in X509 format
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public X509Certificate getRootCACertificate() throws KeyStoreException, NoSuchProviderException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(ROOT_CA_CERTIFICATE_ALIAS);
    }

    /**
     * @return AAM certificate in X509 format
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public X509Certificate getAAMCertificate() throws KeyStoreException, NoSuchProviderException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(CERTIFICATE_ALIAS);
    }

    /**
     * @return Retrieves AAM's public key from provisioned JavaKeyStore
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public PublicKey getAAMPublicKey() throws NoSuchProviderException, KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return pkcs12Store.getCertificate(CERTIFICATE_ALIAS).getPublicKey();
    }

    /**
     * @return retrieves AAM's private key from provisioned JavaKeyStore
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public PrivateKey getAAMPrivateKey() throws NoSuchProviderException, KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (PrivateKey) pkcs12Store.getKey(CERTIFICATE_ALIAS, PV_KEY_PASSWORD.toCharArray());
    }


    private ContentSigner contentSignerPreparation() {
        PrivateKey privKey;
        try {
            privKey = this.getAAMPrivateKey();
        } catch (NoSuchAlgorithmException | CertificateException | NoSuchProviderException
                | KeyStoreException | UnrecoverableKeyException | IOException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }

        ContentSigner sigGen;
        try {
            sigGen = new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM).setProvider
                    (CryptoHelper.PROVIDER_NAME).build
                    (privKey);
        } catch (OperatorCreationException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }

        return sigGen;
    }

    public X509Certificate generateCertificateFromCSR(PKCS10CertificationRequest request, boolean flagCA) throws
            CertificateException {

        BasicConstraints basicConstraints;

        X509Certificate caCert;
        try {
            caCert = this.getRootCACertificate();
        } catch (KeyStoreException | NoSuchProviderException | IOException | NoSuchAlgorithmException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }

        JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(request);

        PublicKey publicKey;
        try {
            publicKey = jcaRequest.getPublicKey();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }

        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        if (flagCA)
            basicConstraints = new BasicConstraints(0);
        else
            basicConstraints = new BasicConstraints(false);

        X509v3CertificateBuilder certGen;
        try {
            certGen = new JcaX509v3CertificateBuilder(
                    issuer,
                    BigInteger.valueOf(1),
                    new Date(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis() + certificateValidityPeriod),
                    jcaRequest.getSubject(),
                    publicKey)
                    .addExtension(
                            new ASN1ObjectIdentifier("2.5.29.19"),
                            false,
                            basicConstraints);
        } catch (CertIOException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }

        ContentSigner sigGen = contentSignerPreparation();

        return new JcaX509CertificateConverter()
                .setProvider(CryptoHelper.PROVIDER_NAME)
                .getCertificate(certGen
                        .build(sigGen));
    }

}
