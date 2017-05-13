package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.commons.Platform;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.constants.AAMConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.List;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web service associated to other AAM features
 *
 * @author Mikołaj Dobski (PSNC)
 */
@RestController
public class OtherController {

    private static final Log log = LogFactory.getLog(OtherController.class);
    private RegistrationManager registrationManager;
    private User user;
    private PlatformRepository platformRepository;

    @Autowired
    public OtherController(RegistrationManager registrationManager, PlatformRepository platformRepository) {
        this.registrationManager = registrationManager;
        this.platformRepository = platformRepository;
    }


    @RequestMapping(value = AAMConstants.AAM_GET_CA_CERTIFICATE, method = RequestMethod.GET)
    public ResponseEntity<String> getCACert() {
        try {
            return ResponseEntity.status(HttpStatus.OK).body(registrationManager.getAAMCert());
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException |
                NoSuchProviderException e) {
            log.error(e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }


    @RequestMapping(value = "/aams/available", method = RequestMethod.GET)
    public ResponseEntity<List<Platform>> availableAAMs() {

        try {
            return ResponseEntity.status(HttpStatus.OK).body(platformRepository.findAll());
        } catch (Exception e) {
            log.error(e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

}

