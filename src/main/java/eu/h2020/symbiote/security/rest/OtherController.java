package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.commons.Platform;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.session.AAM;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
import java.util.ArrayList;
import java.util.List;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web service associated to other AAM features
 *
 * @author Mikołaj Dobski (PSNC)
 */
@RestController
public class OtherController {

    private static final Log log = LogFactory.getLog(OtherController.class);
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface:/paam}")
    String platformAAMSuffixAtInterWorkingInterface = "/paam";
    @Value("${aam.environment.interworkingInterfacePort::8101}")
    String interworkingInterfacePort = ":8101";
    private RegistrationManager registrationManager;
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

    @RequestMapping(value = AAMConstants.AAM_GET_AVAILABLE_AAMS, method = RequestMethod.GET, produces =
            "application/json")
    public ResponseEntity<List<AAM>> getAvailableAAMs() {
        List<AAM> availableAAMs = new ArrayList<>();
        try {
            // Core AAM
            Certificate coreCertificate = new Certificate(registrationManager.getAAMCert());
            // fetching the identifier from certificate

            /* TODO R3 think of a better resolving the core instance from the certificate.
            String coreAAMInstanceIdentifier = coreCertificate.getX509().getSubjectX500Principal()
                    .getName("RFC1779").split(",")[1].split("=")[1];
            */

            // adding core aam info to the response
            availableAAMs.add(new AAM(coreInterfaceAddress,
                    AAMConstants.AAM_CORE_AAM_FRIENDLY_NAME,
                    AAMConstants.AAM_CORE_AAM_INSTANCE_ID,
                    coreCertificate));

            // registered platforms' AAMs
            for (Platform platform : platformRepository.findAll()) {
                // TODO R3 include the real platform certificate
                AAM platformAAM = new AAM("temporary", platform.getPlatformInstanceFriendlyName(), platform
                        .getPlatformInstanceId(), platform.getPlaformAAMCertificate());
                // building paam path
                StringBuilder paamAddress = new StringBuilder(platform.getPlatformInterworkingInterfaceAddress());
                paamAddress.append(platformAAMSuffixAtInterWorkingInterface);
                // setting the AAM properly
                platformAAM.setAamAddress(paamAddress.toString());
                // add the platform AAM entrypoint to the results
                availableAAMs.add(platformAAM);
            }
            return new ResponseEntity<>(availableAAMs, HttpStatus.OK);
        } catch (Exception e) {
            log.error(e);
            return new ResponseEntity<>(new ArrayList<AAM>(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}