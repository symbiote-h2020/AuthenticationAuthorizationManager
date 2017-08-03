package eu.h2020.symbiote.security.unit.trustchainvalidation;

import eu.h2020.symbiote.security.AbstractAAMTestSuite;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.io.IOException;

import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class TrustChainValidationTests extends
        AbstractAAMTestSuite {

    @Autowired
    private ValidationHelper validationHelper;

    // Leaf Certificate
    private static String applicationCertificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIB6jCCAZCgAwIBAgIEWWyv1DAKBggqhkjOPQQDAjB0MRQwEgYJKoZIhvcNAQkB\n" +
            "FgVhQGIuYzENMAsGA1UECxMEdGVzdDENMAsGA1UEChMEdGVzdDENMAsGA1UEBxME\n" +
            "dGVzdDENMAsGA1UECBMEdGVzdDELMAkGA1UEBhMCUEwxEzARBgNVBAMTCnBsYXRm\n" +
            "b3JtLTEwHhcNMTcwNzE3MTIzODUxWhcNMTgwNzE3MTIzODUxWjCBhTEUMBIGCSqG\n" +
            "SIb3DQEJARYFYUBiLmMxCzAJBgNVBAYTAklUMQ0wCwYDVQQIDAR0ZXN0MQ0wCwYD\n" +
            "VQQHDAR0ZXN0MQ0wCwYDVQQKDAR0ZXN0MQ0wCwYDVQQLDAR0ZXN0MSQwIgYDVQQD\n" +
            "DBthcHBsaWNhdGlvbi1wbGF0Zm9ybS0xLTEtYzEwWTATBgcqhkjOPQIBBggqhkjO\n" +
            "PQMBBwNCAASGxfZa6ivSR4+BWBHRh94MNURAXBpBrZECvMH/rcgm8/aTHach6ncN\n" +
            "fw8VY2RNf3l/runJOQQH/3xGEisDIY7fMAoGCCqGSM49BAMCA0gAMEUCIDrJxAet\n" +
            "0IqR6aiJc87BS1faA8Ijl7kQnkphPOazKiXXAiEAoVHhBTNZACa4+2/0OsSg2k2P\n" +
            "jExF7CXu6SB/rvivAXk=\n" +
            "-----END CERTIFICATE-----\n";

    //  Intermediate Certificate (the good one)
    private static  String rightSigningAAMCertificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIICBzCCAaqgAwIBAgIEW/ehcjAMBggqhkjOPQQDAgUAMEkxDTALBgNVBAcTBHRl\n" +
            "c3QxDTALBgNVBAoTBHRlc3QxDTALBgNVBAsTBHRlc3QxGjAYBgNVBAMMEVN5bWJJ\n" +
            "b1RlX0NvcmVfQUFNMB4XDTE3MDYxMzEwMjkxOVoXDTI3MDYxMTEwMjkxOVowdDEU\n" +
            "MBIGCSqGSIb3DQEJARYFYUBiLmMxDTALBgNVBAsTBHRlc3QxDTALBgNVBAoTBHRl\n" +
            "c3QxDTALBgNVBAcTBHRlc3QxDTALBgNVBAgTBHRlc3QxCzAJBgNVBAYTAlBMMRMw\n" +
            "EQYDVQQDEwpwbGF0Zm9ybS0xMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7eSa\n" +
            "IbqcQJsiQdfEzOZFnfUPejSJJCoTxI+vafbKWrrVRQSdKw0vV/Rddgu5IxVNqdWK\n" +
            "lkwirWlMZXLRGqfwh6NTMFEwHwYDVR0jBBgwFoAUNiFCbRtr/vdc4oaiASrBxosU\n" +
            "uZQwDwYDVR0TBAgwBgEB/wIBADAdBgNVHQ4EFgQUdxSdPTW56zEh0Wuqfx26J4ve\n" +
            "QWwwDAYIKoZIzj0EAwIFAANJADBGAiEAv/MmIW8g5I6dVOjoRins750rxnt9OcpP\n" +
            "VvOHShi5YqYCIQDRvpwyWySQ0U0LKjzob/GwqeYJ+6el8x1xbpJhs0Uweg==\n" +
            "-----END CERTIFICATE-----\n";

    //  Intermediate Certificate (the bad one)
    private static  String wrongSigningAAMCertificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBrTCCAVOgAwIBAgIEWT/PizAKBggqhkjOPQQDAjBJMQ0wCwYDVQQHEwR0ZXN0\n" +
            "MQ0wCwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MRowGAYDVQQDDBFTeW1iSW9U\n" +
            "ZV9Db3JlX0FBTTAeFw0xNzA2MTMxMTQyMjVaFw0yNzA2MTMxMTQyMjVaMHQxFDAS\n" +
            "BgkqhkiG9w0BCQEWBWFAYi5jMQ0wCwYDVQQLEwR0ZXN0MQ0wCwYDVQQKEwR0ZXN0\n" +
            "MQ0wCwYDVQQHEwR0ZXN0MQ0wCwYDVQQIEwR0ZXN0MQswCQYDVQQGEwJQTDETMBEG\n" +
            "A1UEAxMKcGxhdGZvcm0tMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMaODIy1\n" +
            "sOOJdmd7stBIja4eGn9eKUEU/LVwocfiu6EW1pnZraI1Uqpu7t9CNjsFxWi/jDVg\n" +
            "kViBAy/bg9kzocMwCgYIKoZIzj0EAwIDSAAwRQIhAIBz2MJoERVLmYxs7P0B5dCn\n" +
            "yqWmjrYhosEiCUoVxIQVAiAwhZdM0XAeGGfTP2WsXGKFtcw/nL/gzvYSjAAGbkyx\n" +
            "sw==\n" +
            "-----END CERTIFICATE-----\n";

    private static Log log = LogFactory.getLog(TrustChainValidationTests.class);

    @Test
    public void validateCertificateChainSuccess() throws
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException {

        X509Certificate rightSigningAAMCertificate = CryptoHelper.convertPEMToX509(rightSigningAAMCertificatePEM);
        boolean trustChainValidationStatus = validationHelper.isTrusted(rightSigningAAMCertificate, applicationCertificatePEM);
        assertEquals(true, trustChainValidationStatus);
    }

    @Test
    public void validateCertificateChainFailure() throws
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException {

        X509Certificate signingAAMCertificate = CryptoHelper.convertPEMToX509(wrongSigningAAMCertificatePEM);
        boolean trustChainValidationStatus = validationHelper.isTrusted(signingAAMCertificate, applicationCertificatePEM);

        assertEquals(false, trustChainValidationStatus);
    }
}

