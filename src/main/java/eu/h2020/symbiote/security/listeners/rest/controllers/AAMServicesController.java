package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IAAMServices;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IGetComponentCertificate;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Map;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web service associated to other AAM features
 *
 * @author Mikołaj Dobski (PSNC)
 */
@RestController
public class AAMServicesController implements IAAMServices, IGetComponentCertificate {

    private static final Log log = LogFactory.getLog(AAMServicesController.class);
    private CertificationAuthorityHelper certificationAuthorityHelper;
    private AAMServices aamServices;

    @Autowired
    public AAMServicesController(CertificationAuthorityHelper certificationAuthorityHelper, AAMServices aamServices) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.aamServices = aamServices;
    }

    public ResponseEntity<String> getComponentCertificate() {
        try {
            return ResponseEntity.status(HttpStatus.OK).body(certificationAuthorityHelper.getAAMCert());
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException |
                NoSuchProviderException e) {
            log.error(e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    public ResponseEntity<AvailableAAMsCollection> getAvailableAAMs() {
        Map<String, AAM> result;
        try {
            result = aamServices.getAvailableAAMs();
        } catch (Exception e) {
            log.error(e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(new AvailableAAMsCollection(result), HttpStatus.OK);
    }
}