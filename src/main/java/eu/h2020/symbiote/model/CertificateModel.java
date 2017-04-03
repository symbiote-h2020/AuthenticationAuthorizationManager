package eu.h2020.symbiote.model;

import eu.h2020.symbiote.commons.Application;
import org.springframework.data.annotation.Id;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import eu.h2020.symbiote.commons.RegistrationManager;

/**
 * Platform AAM certificate entity definition for database persistence.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see Application
 */
public class CertificateModel{

    RegistrationManager registrationManager = new RegistrationManager();

    private String pemCertificate;
    private Date asyncNotAfter;

    public CertificateModel(String pemCertificate) throws CertificateException, NoSuchProviderException {
        this.pemCertificate = pemCertificate;
    }

    public CertificateModel(X509Certificate certificate) throws IOException, CertificateException, NoSuchProviderException {
        this.pemCertificate = registrationManager.convertX509ToPEM(certificate);
    }

    public CertificateModel(String pemCertificate, Date asyncNotAfter) throws CertificateException, NoSuchProviderException {
        this.pemCertificate = pemCertificate;
        this.asyncNotAfter = asyncNotAfter;
    }

    public CertificateModel(X509Certificate certificate,Date asyncNotAfter) throws IOException, CertificateException, NoSuchProviderException {
        this.pemCertificate = registrationManager.convertX509ToPEM(certificate);
        this.asyncNotAfter = asyncNotAfter;
    }

    @Id
    public String getPemCertificate() {
        return this.pemCertificate;
    }

    public X509Certificate getCertificate() throws IOException, CertificateException {
        return registrationManager.convertPEMToX509(this.pemCertificate);
    }

    public void setPemCertificate(String pemCertificate) {
        this.pemCertificate = pemCertificate;
    }

    public void setPemCertificate(X509Certificate certificate) throws IOException {
        this.pemCertificate = registrationManager.convertX509ToPEM(certificate);
    }

    public Date getAsyncNotAfter() {
        return asyncNotAfter;
    }

    public void setAsyncNotAfter(Date asyncNotAfter) {
        this.asyncNotAfter = asyncNotAfter;
    }
}
