package eu.h2020.symbiote.security.listeners.rest;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.interfaces.IAAMServices;
import eu.h2020.symbiote.security.communication.interfaces.IGetComponentCertificate;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web service associated to other AAM features
 *
 * @author Mikołaj Dobski (PSNC)
 */
@RestController
public class AAMServices implements IAAMServices, IGetComponentCertificate {

    private static final Log log = LogFactory.getLog(AAMServices.class);
    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    String coreInterfaceAddress;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface:/paam}")
    String platformAAMSuffixAtInterWorkingInterface = "/paam";
    @Value("${aam.environment.interworkingInterfacePort::8101}")
    String interworkingInterfacePort = ":8101";
    private CertificationAuthorityHelper certificationAuthorityHelper;
    private PlatformRepository platformRepository;

    @Autowired
    public AAMServices(CertificationAuthorityHelper certificationAuthorityHelper, PlatformRepository
            platformRepository) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.platformRepository = platformRepository;
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

    public Map<String, AAM> getAvailableAAMs() {
        Map<String, AAM> availableAAMs = new TreeMap<>();
        try {
            // Core AAM
            Certificate coreCertificate = new Certificate(certificationAuthorityHelper.getAAMCert());

            // adding core aam info to the response
            availableAAMs.put(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID, new AAM(coreInterfaceAddress,
                    SecurityConstants.AAM_CORE_AAM_FRIENDLY_NAME,
                    SecurityConstants.AAM_CORE_AAM_INSTANCE_ID,
                    coreCertificate));

            // registered platforms' AAMs
            for (Platform platform : platformRepository.findAll()) {
                // TODO R3 include the real platform certificate
                AAM platformAAM = new AAM("temporary", platform.getPlatformInstanceFriendlyName(), platform
                        .getPlatformInstanceId(), platform.getPlatformAAMCertificate());
                // building paam path
                StringBuilder paamAddress = new StringBuilder(platform.getPlatformInterworkingInterfaceAddress());
                paamAddress.append(platformAAMSuffixAtInterWorkingInterface);
                // setting the AAM properly
                platformAAM.setAamAddress(paamAddress.toString());
                // add the platform AAM entrypoint to the results
                availableAAMs.put(platformAAM.getAamInstanceId(), platformAAM);
            }
            return availableAAMs;
        } catch (Exception e) {
            log.error(e);
            return new HashMap<>();
        }
    }
}