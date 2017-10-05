package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IAAMServices;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IGetComponentCertificate;
import eu.h2020.symbiote.security.services.AAMServices;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
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
    private AAMServices aamServices;

    @Autowired
    public AAMServicesController(AAMServices aamServices) {
        this.aamServices = aamServices;
    }

    @ApiOperation(value = "Get component certificate", response = String.class)
    @ApiResponses({
            @ApiResponse(code = 500, message = "Could not retrieve Component Certificate"),
            @ApiResponse(code = 404, message = "Certificate could not be found")})
    public ResponseEntity<String> getComponentCertificate(@PathVariable String componentIdentifier,
                                                          @PathVariable String deploymentIdentifier) {
        try {
            String certificate = aamServices.getComponentCertificate(componentIdentifier, deploymentIdentifier);

            // not found
            if (certificate.isEmpty())
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("");
            // found
            return ResponseEntity.status(HttpStatus.OK).body(certificate);
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException |
                NoSuchProviderException | AAMException e) {
            log.error(e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @ApiOperation(value = "Returns collection of available deployments (their AAMs and components)", response = AvailableAAMsCollection.class)
    @ApiResponses({
            @ApiResponse(code = 500, message = "Internal AAM Error")})
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