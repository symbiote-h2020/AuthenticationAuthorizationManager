package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;


/**
 * Certificate related set of functions.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
@Component
public class RegistrationManager {

    private static Log log = LogFactory.getLog(RegistrationManager.class);
    // Provider is used from the implementation
    private final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    @Value("${aam.security.KEY_PAIR_GEN_ALGORITHM}")
    private String KEY_PAIR_GEN_ALGORITHM;
    @Value("${aam.security.CURVE_NAME}")
    private String CURVE_NAME;
    @Value("${aam.security.SIGNATURE_ALGORITHM}")
    private String SIGNATURE_ALGORITHM;
    @Value("${aam.security.KEY_STORE_FILE_NAME}")
    private String KEY_STORE_FILE_NAME;
    @Value("${aam.security.CERTIFICATE_ALIAS}")
    private String CERTIFICATE_ALIAS;

    @Value("${aam.security.KEY_STORE_PASSWORD}")
    private String KEY_STORE_PASSWORD;
    @Value("${aam.security.PV_KEY_PASSWORD}")
    private String PV_KEY_PASSWORD;


    public RegistrationManager() throws CertificateException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * @return resolves the deployment type using the AAM certificate
     */
    public IssuingAuthorityType getDeploymentType() {
        String aamInstanceIdentifier = getAAMInstanceIdentifier();
        if (aamInstanceIdentifier.isEmpty())
            return IssuingAuthorityType.NULL;
        if (aamInstanceIdentifier.equals(AAMConstants.AAM_CORE_AAM_INSTANCE_ID))
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

    public KeyPair createKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(CURVE_NAME);
        KeyPairGenerator g = KeyPairGenerator.getInstance(KEY_PAIR_GEN_ALGORITHM, PROVIDER_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        return g.generateKeyPair();
    }

    public String convertX509ToPEM(X509Certificate signedCertificate) throws IOException {
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(signedCertificate);
        pemWriter.close();
        return signedCertificatePEMDataStringWriter.toString();
    }

    public String convertPrivateKeyToPEM(PrivateKey privateKey) throws IOException {
        StringWriter privateKeyPEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(privateKeyPEMDataStringWriter);
        pemWriter.writeObject(privateKey);
        pemWriter.close();
        return privateKeyPEMDataStringWriter.toString();
    }

    public X509Certificate convertPEMToX509(String pemCertificate) throws IOException, CertificateException {
        StringReader reader = new StringReader(pemCertificate);
        PemReader pr = new PemReader(reader);
        PemObject pemObject = pr.readPemObject();
        X509CertificateHolder certificateHolder = new X509CertificateHolder(pemObject.getContent());
        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certificateHolder);
    }

    public PrivateKey convertPEMToPrivateKey(String pemPrivatekey) throws IOException, CertificateException {
        StringReader reader = new StringReader(pemPrivatekey);
        PEMParser pemParser = new PEMParser(reader);
        Object o = pemParser.readObject();
        KeyPair kp = new JcaPEMKeyConverter().setProvider(PROVIDER_NAME).getKeyPair((PEMKeyPair) o);
        return kp.getPrivate();
    }

    private X500NameBuilder createStdBuilder(String givenName) throws NoSuchProviderException {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.NAME, givenName);
        try {
            builder.addRDN(BCStyle.OU,
                    getAAMCertificate().getSubjectX500Principal().getName().split(",")[1].split("=")[1]);
            builder.addRDN(BCStyle.O,
                    getAAMCertificate().getSubjectX500Principal().getName().split(",")[2].split("=")[1]);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            log.error(e);
            return null;
        }
        return builder;
    }

    public X509Certificate createECCert(String username, PublicKey pubKey) throws NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException,
            OperatorCreationException {

        // retrieves AAM private key from keystore
        PrivateKey privKey = this.getAAMPrivateKey();

        // distinguished name table.
        X500NameBuilder issuerBuilder = createStdBuilder(getAAMInstanceIdentifier());
        X500NameBuilder subjectBuilder = createStdBuilder(username);

        // create the certificate - version 3
        ContentSigner sigGen = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build
                (privKey); //

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                issuerBuilder.build(),
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + 1L * 365L * 24L * 60L * 60L * 1000L),
                subjectBuilder.build(),
                pubKey)
                .addExtension(
                        new ASN1ObjectIdentifier("2.5.29.19"),
                        false,
                        new BasicConstraints(false));// true if it is allowed to sign other certs;

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certGen
                .build(sigGen));

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", PROVIDER_NAME);
        cert = (X509Certificate) certFact.generateCertificate(bIn);

        return cert;
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
        return this.convertX509ToPEM(getAAMCertificate());
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

    public X509Certificate generateCertificateFromCSR(PKCS10CertificationRequest request) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException, OperatorCreationException {

        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        X509Certificate caCert = (X509Certificate) pkcs12Store.getCertificate(CERTIFICATE_ALIAS);
        X500Name issuer = new X500Name( caCert.getSubjectX500Principal().getName() );
        PrivateKey privKey = this.getAAMPrivateKey();
        JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(request);

        ContentSigner sigGen = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build
                (privKey);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + 1L * 365L * 24L * 60L * 60L * 1000L),
                jcaRequest.getSubject(),
                jcaRequest.getPublicKey())
                .addExtension(
                        new ASN1ObjectIdentifier("2.5.29.19"),
                        false,
                        new BasicConstraints(false));

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certGen
                .build(sigGen));

        return cert;
    }

}
