package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * Certificate related set of functions.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class CertificationAuthorityHelper {
    private static final Long certificateValidityPeriod = 1L * 365L * 24L * 60L * 60L * 1000L;
    private static Log log = LogFactory.getLog(CertificationAuthorityHelper.class);

    
    private final String KEY_STORE_FILE_NAME;
    private final String ROOT_CA_CERTIFICATE_ALIAS;
    private final String CERTIFICATE_ALIAS;
    private final String KEY_STORE_PASSWORD;
    private final String PV_KEY_PASSWORD;
	private ApplicationContext ctx;

    public CertificationAuthorityHelper(@Value("${aam.security.KEY_STORE_FILE_NAME}") String key_store_file_name,
                                        @Value("${aam.security.ROOT_CA_CERTIFICATE_ALIAS}") String root_ca_certificate_alias,
                                        @Value("${aam.security.CERTIFICATE_ALIAS}") String certificate_alias,
                                        @Value("${aam.security.KEY_STORE_PASSWORD}") String key_store_password,
                                        @Value("${aam.security.PV_KEY_PASSWORD}") String pv_key_password,
                                        ApplicationContext ctx) throws
            CertificateException,
            NoSuchProviderException,
            SecurityMisconfigurationException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            IOException {
        KEY_STORE_FILE_NAME = key_store_file_name;
        ROOT_CA_CERTIFICATE_ALIAS = root_ca_certificate_alias;
        CERTIFICATE_ALIAS = certificate_alias;
        KEY_STORE_PASSWORD = key_store_password;
        PV_KEY_PASSWORD = pv_key_password;
		this.ctx = ctx;
        List<String> activeProfiles = Arrays.asList(ctx.getEnvironment().getActiveProfiles());
        if (activeProfiles.size() != 1)
            throw new SecurityMisconfigurationException("You have to have only one active profile. Please check in your bootstrap.properties 'spring.profiles.active'.");
        Security.addProvider(new BouncyCastleProvider());
        switch (getDeploymentType()) {
            case CORE:
                if (!activeProfiles.get(0).equals("core"))
                    throw new SecurityMisconfigurationException("You are loading Core certificate. In your bootstrap.properties, following line should be present: 'spring.profiles.active=core'");
                break;
            case PLATFORM:
                if (certificate_alias.equals(root_ca_certificate_alias))
                    throw new SecurityMisconfigurationException("This AAM's certificate must be different from Core AAM - root certificate");
                if (!activeProfiles.get(0).equals("platform"))
                    throw new SecurityMisconfigurationException("You are loading Platform certificate. In your bootstrap.properties, following line must be present: 'spring.profiles.active=platform'");
                break;
            case SMART_SPACE:
                if (certificate_alias.equals(root_ca_certificate_alias))
                    throw new SecurityMisconfigurationException("This AAM's certificate must be different from Core AAM - root certificate");
                if (!activeProfiles.get(0).equals("smart_space"))
                    throw new SecurityMisconfigurationException("You are loading Smart Space certificate. In your bootstrap.properties, following line must be present:'spring.profiles.active=smart_space'");
                break;
            case NULL:
                throw new CertificateException("Failed to initialize AAM using given symbiote keystore");
        }
        PrivateKey aamPrivateKey = getAAMPrivateKey();
        if (aamPrivateKey == null
                || aamPrivateKey.getAlgorithm() == null)
            throw new SecurityMisconfigurationException(SecurityMisconfigurationException.AAM_PRIVATE_KEY_NOT_FOUND_IN_GIVEN_CONFIGURATION);
        if (!aamPrivateKey.getAlgorithm().equals("EC"))
            throw new SecurityMisconfigurationException(SecurityMisconfigurationException.CONFIGURATION_POINTS_TO_WRONG_CERTIFICATE);

    }

    /**
     * @return resolves the deployment type using the AAM certificate
     */
    public IssuingAuthorityType getDeploymentType() {
        String aamInstanceIdentifier = getAAMInstanceIdentifier();
        if (aamInstanceIdentifier.isEmpty())
            return IssuingAuthorityType.NULL;
        if (aamInstanceIdentifier.equals(SecurityConstants.CORE_AAM_INSTANCE_ID))
            return IssuingAuthorityType.CORE;
        if (aamInstanceIdentifier.startsWith(SecurityConstants.SMART_SPACE_IDENTIFIER_PREFIX))
            return IssuingAuthorityType.SMART_SPACE;
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
    public String getAAMCert() throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
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
    public String getRootCACert() throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        return CryptoHelper.convertX509ToPEM(getRootCACertificate());
    }

    /**
     * @return RootCA certificate in X509 format
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public X509Certificate getRootCACertificate() throws
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            NoSuchAlgorithmException,
            CertificateException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        if(ctx.getResource(KEY_STORE_FILE_NAME).exists()) {
	        	pkcs12Store.load(ctx.getResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        } else {
        		pkcs12Store.load(new ClassPathResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        }
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
    public X509Certificate getAAMCertificate() throws
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            NoSuchAlgorithmException,
            CertificateException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        if(ctx.getResource(KEY_STORE_FILE_NAME).exists()) {
	        	pkcs12Store.load(ctx.getResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        } else {
        		pkcs12Store.load(new ClassPathResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        }
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
    public PublicKey getAAMPublicKey() throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        if(ctx.getResource(KEY_STORE_FILE_NAME).exists()) {
        		pkcs12Store.load(ctx.getResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        } else {
        		pkcs12Store.load(new ClassPathResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        }
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
    public PrivateKey getAAMPrivateKey() throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        if(ctx.getResource(KEY_STORE_FILE_NAME).exists()) {
        		pkcs12Store.load(ctx.getResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        } else {
        		pkcs12Store.load(new ClassPathResource(KEY_STORE_FILE_NAME).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        }
        return (PrivateKey) pkcs12Store.getKey(CERTIFICATE_ALIAS, PV_KEY_PASSWORD.toCharArray());
    }


    private ContentSigner contentSignerPreparation() {
        PrivateKey privKey;
        try {
            privKey = this.getAAMPrivateKey();
        } catch (NoSuchAlgorithmException |
                CertificateException |
                NoSuchProviderException |
                KeyStoreException |
                UnrecoverableKeyException |
                IOException e) {
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
            caCert = this.getAAMCertificate();
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
        if (flagCA)
            basicConstraints = new BasicConstraints(0);
        else
            basicConstraints = new BasicConstraints(false);

        X509v3CertificateBuilder certGen;
        try {
            certGen = new JcaX509v3CertificateBuilder(
                    caCert,
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

    public boolean isServiceCertificateChainTrusted(String foreignTokenIssuerCertificateString) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {

        X509Certificate rootCertificate = getRootCACertificate();

        // for foreign tokens issued by Core AAM
        if (foreignTokenIssuerCertificateString.equals(CryptoHelper.convertX509ToPEM(rootCertificate)))
            return true;

        // convert certificates to X509
        X509Certificate foreignTokenIssuerCertificate = CryptoHelper.convertPEMToX509(foreignTokenIssuerCertificateString);

        // Create the selector that specifies the starting certificate
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(foreignTokenIssuerCertificate);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        TrustAnchor trustAnchor = new TrustAnchor(rootCertificate, null);
        trustAnchors.add(trustAnchor);

        // List of certificates to build the path from
        List<X509Certificate> certsOnPath = new ArrayList<>();
        certsOnPath.add(foreignTokenIssuerCertificate);

        /*
         * If build() returns successfully, the certificate is valid. More details
         * about the valid path can be obtained through the PKIXCertPathBuilderResult.
         * If no valid path can be found, a CertPathBuilderException is thrown.
         */
        try {
            // Create the selector that specifies the starting certificate
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, target);
            // Disable CRL checks (this is done manually as additional step)
            params.setRevocationEnabled(false);

            // Specify a list of certificates on path
            CertStore validatedPathCertsStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(certsOnPath), "BC");
            params.addCertStore(validatedPathCertsStore);

            // Build and verify the certification chain
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(params);
            // path should have 1 cert in symbIoTe architecture
            return result.getCertPath().getCertificates().size() == 1;
        } catch (CertPathBuilderException | InvalidAlgorithmParameterException e) {
            log.info(e);
            return false;
        }
    }
}
