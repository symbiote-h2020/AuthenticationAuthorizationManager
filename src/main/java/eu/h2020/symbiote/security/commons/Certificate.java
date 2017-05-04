package eu.h2020.symbiote.security.commons;

import org.springframework.data.annotation.Id;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * SymbIoTe certificate with stored PEM value
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class Certificate {

    @Id
    private String cerficateString;

    /**
     * required by JPA
     */
    public Certificate() {
        // required by JPA
    }

    /**
     * @param cerficateString in PEM format
     */
    public Certificate(String cerficateString) {
        this.cerficateString = cerficateString;
    }

    /**
     * @return retrieve the X509 certificate that corresponds to the stored string
     * @throws CertificateException
     */
    public X509Certificate getX509() throws CertificateException {
        InputStream stream = new ByteArrayInputStream(this.getCerficateString().getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(stream);
    }

    /**
     * @return in PEM format
     */
    public String getCerficateString() {
        return cerficateString;
    }

    /**
     * @param cerficateString in PEM format
     */
    public void setCerficateString(String cerficateString) {
        this.cerficateString = cerficateString;
    }

    @Override
    public String toString() {
        return this.cerficateString;
    }
}
