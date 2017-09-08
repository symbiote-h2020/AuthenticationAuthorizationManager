package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IAAMServices;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IGetComponentCertificate;
import eu.h2020.symbiote.security.services.AAMServices;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
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
@Api(value = "/docs/aamservices", description = "Exposes services provided by AAM", produces = "application/json")
public class AAMServicesController implements IAAMServices, IGetComponentCertificate {

    private static final Log log = LogFactory.getLog(AAMServicesController.class);
    private CertificationAuthorityHelper certificationAuthorityHelper;
    private AAMServices aamServices;

    @Autowired
    public AAMServicesController(CertificationAuthorityHelper certificationAuthorityHelper, AAMServices aamServices) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.aamServices = aamServices;
    }

    @ApiOperation(value = "Get Component Certificate", response = String.class)
    @ApiResponse(code = 500, message = "Could not create Component Certificate")
    public ResponseEntity<String> getComponentCertificate() {
        try {
            return ResponseEntity.status(HttpStatus.OK).body(certificationAuthorityHelper.getAAMCert());
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException |
                NoSuchProviderException e) {
            log.error(e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @ApiOperation(value = "Returns collection of available AAMs", response = AvailableAAMsCollection.class)
    @ApiResponse(code = 500, message = "Internal AAM Error")
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