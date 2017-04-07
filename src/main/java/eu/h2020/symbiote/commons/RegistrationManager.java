package eu.h2020.symbiote.commons;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.util.Date;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Component;

/**
 * Certificate related set of functions.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Component
public class RegistrationManager {

    private static final String KEY_PAIR_GEN_ALGORITHM = "ECDSA";
    private static final String CURVE_NAME = "secp256r1";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String ORG_NAME = "SYMBIOTE";
    private static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    private static final String KEY_STORE_FILE_NAME = "PlatformAAM.keystore";
    private static final String KEY_STORE_ALIAS = "Platform AAM keystore";
    private static final char[] KEY_STORE_PASSWD = { '1', '2', '3', '4', '5','6','7',}; // Where do we want to store this two pwds?
    private static final char[] KEY_STORE_PV_PASSWD = { 'a', 'b', 'c', 'd', 'e','f','g'};

    public RegistrationManager() throws CertificateException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
    }

    public KeyPair createKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(CURVE_NAME);
        KeyPairGenerator g = KeyPairGenerator.getInstance(KEY_PAIR_GEN_ALGORITHM, PROVIDER_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = g.generateKeyPair();
        return keyPair;
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
        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate( certificateHolder );
    }

    public PrivateKey convertPEMToPrivateKey(String pemPrivatekey) throws IOException, CertificateException {
        StringReader reader = new StringReader(pemPrivatekey);
        PEMParser pemParser = new PEMParser(reader);
        Object o = pemParser.readObject();
        KeyPair kp = new JcaPEMKeyConverter().setProvider(PROVIDER_NAME).getKeyPair((PEMKeyPair) o);
        return kp.getPrivate();
    }

    private X500NameBuilder createStdBuilder(String givenName)
    {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.NAME, givenName);
        builder.addRDN(BCStyle.O, ORG_NAME);
        return builder;
    }

    public X509Certificate createECCert(String applicationUsername, PublicKey pubKey) throws NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException,
            OperatorCreationException {

        // retrieves Platform AAM private key from keystore
        PrivateKey privKey = this.getPlatformAAMPrivateKey();

        // distinguished name table.
        X500NameBuilder issuerBuilder = createStdBuilder("PlatformAAM");
        X500NameBuilder subjectBuilder = createStdBuilder(applicationUsername);

        // create the certificate - version 3
        ContentSigner sigGen = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build(privKey); //

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                issuerBuilder.build(),
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + 1L * 365L * 24L * 60L * 60L * 1000L),
                subjectBuilder.build(),
                pubKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certGen.build(sigGen));

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", PROVIDER_NAME);
        cert = (X509Certificate)certFact.generateCertificate(bIn);

        System.out.println(cert.toString()); //TODO: Delete this

        return cert;
    }

    // FIXME: THIS IS NOT THE WAY IT'GONNA BE IN FUTURE. JUST FOR TEST PURPOSES. Symbiote CORE is the root CA and IT should provide any Platform AAM a certificate. Platform AAM is not going to issue itself a certificate!
    // ONLY FOR TESTS
    /**
     * Used to generate the Platform AAM Certificate and private key and store them on a file.
     * Note: The Platform AAM private key will be retrieved any time Platform AAM (which acts as an intermediate CA) will generate a certificate for a registering application.
     *
     * @implNote This function is only used ONE TIME. After that, PAAM certificate and PV key are stored in a file.
     * @see eu.h2020.symbiote.commons.RegistrationManager#createECCert(String, PublicKey)
     */
    public void createSelfSignedPlatformAAMECCert() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            OperatorCreationException,
            CertificateException,
            IOException,
            KeyStoreException {

        // Create a pair of keys for the Platform AAM which will beave as Intermediate CA
        KeyPair keyPair = createKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        // distinguished name table.
        X500NameBuilder builder = createStdBuilder("PlatformAAM");

        // create the certificate - version 3
        ContentSigner sigGen = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER_NAME).build(privKey);

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                builder.build(),
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + 20L * 365L * 24L * 60L * 60L * 1000L), builder.build(),
                pubKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(PROVIDER_NAME).getCertificate(certGen.build(sigGen));

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", PROVIDER_NAME);
        cert = (X509Certificate)certFact.generateCertificate(bIn);

        System.out.println(cert.toString() + '\n' + convertX509ToPEM(cert));

        // Save PlatformAAM certificate to file .pem (not needed, we are using keystore instead)
        //JcaPEMWriter certWriter = new JcaPEMWriter(new PrintWriter(new PrintStream(new FileOutputStream("PlatformAAM_Certificate.pem"))));
        //certWriter.writeObject(privKey);
        //certWriter.close();

        Certificate[] chain = new Certificate[1];
        chain[0] = cert;

        // Save PlatformAAM certificate and private key in a keystore
        KeyStore store = KeyStore.getInstance("PKCS12", PROVIDER_NAME);
        store.load(null, null);
        store.setKeyEntry(KEY_STORE_ALIAS, privKey, KEY_STORE_PV_PASSWD, chain);
        FileOutputStream fOut = new FileOutputStream(KEY_STORE_FILE_NAME); // from console $: openssl pkcs12 -in ./PlatformAAM.keystore to check it
        store.store(fOut, KEY_STORE_PASSWD);

    }

    // ONLY FOR TESTS
    public PublicKey getPlatformAAMPublicKey() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new FileInputStream(KEY_STORE_FILE_NAME), KEY_STORE_PASSWD);
        PublicKey pubKey = pkcs12Store.getCertificate(KEY_STORE_ALIAS).getPublicKey();
        return pubKey;
    }

    // ONLY FOR TESTS
    public PrivateKey getPlatformAAMPrivateKey() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new FileInputStream(KEY_STORE_FILE_NAME), KEY_STORE_PASSWD);
        PrivateKey privKey = (PrivateKey)pkcs12Store.getKey(KEY_STORE_ALIAS, KEY_STORE_PV_PASSWD);
        return privKey;
    }

}
