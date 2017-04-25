package eu.h2020.symbiote.security.commons;

import org.springframework.data.annotation.Id;

import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Date;

/**
 * Platform AAM certificate entity definition for database persistence.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class Certificate {


    private String pemCertificate;
    private Date asyncNotAfter;

    /**
     * required by JPA
     */
    public Certificate() throws CertificateException, NoSuchProviderException {
    }

    public Certificate(String pemCertificate) throws CertificateException, NoSuchProviderException {
        this.pemCertificate = pemCertificate;
    }

    public Certificate(String pemCertificate, Date asyncNotAfter) throws CertificateException,
            NoSuchProviderException {
        this.pemCertificate = pemCertificate;
        this.asyncNotAfter = asyncNotAfter;
    }

    @Id
    public String getPemCertificate() {
        return this.pemCertificate;
    }

    public void setPemCertificate(String pemCertificate) {
        this.pemCertificate = pemCertificate;
    }

    public Date getAsyncNotAfter() {
        return asyncNotAfter;
    }

    public void setAsyncNotAfter(Date asyncNotAfter) {
        this.asyncNotAfter = asyncNotAfter;
    }
}
