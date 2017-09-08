package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

@Service
public class AAMServices {

    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final PlatformRepository platformRepository;
    private final ComponentCertificatesRepository componentCertificatesRepository;
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${aam.environment.coreInterfaceAddress:https://localhost:8443}")
    private String coreInterfaceAddress;
    @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface:/paam}")
    private String platformAAMSuffixAtInterWorkingInterface = "/paam";
    @Value("${aam.environment.interworkingInterfacePort::8101}")
    private String interworkingInterfacePort = ":8101";
    @Value("${symbiote.coreaam.url:localhost}")
    private String coreAAMAddress = "";

    @Autowired
    public AAMServices(CertificationAuthorityHelper certificationAuthorityHelper, PlatformRepository platformRepository, ComponentCertificatesRepository componentCertificatesRepository) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.platformRepository = platformRepository;
        this.componentCertificatesRepository = componentCertificatesRepository;
    }


    public Map<String, AAM> getAvailableAAMs() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        Map<String, AAM> availableAAMs = new TreeMap<>();
        if (certificationAuthorityHelper.getDeploymentType() == IssuingAuthorityType.CORE) {
            // if Core AAM then we know the available AAMs
            Certificate coreCertificate = new Certificate(certificationAuthorityHelper.getAAMCert());

            // adding component certificates
            Map<String, Certificate> componentsCertificatesMap = new HashMap<>();
            List<ComponentCertificate> componentCertificatesFromRepository = componentCertificatesRepository.findAll();
            for (ComponentCertificate certificate : componentCertificatesFromRepository) {
                componentsCertificatesMap.put(certificate.getName(), certificate.getCertificate());
            }

            // adding core aam info to the response
            availableAAMs.put(SecurityConstants.AAM_CORE_AAM_INSTANCE_ID, new AAM(coreInterfaceAddress,
                    SecurityConstants.AAM_CORE_AAM_FRIENDLY_NAME,
                    SecurityConstants.AAM_CORE_AAM_INSTANCE_ID,
                    coreCertificate, componentsCertificatesMap));

            // registered platforms' AAMs
            for (Platform platform : platformRepository.findAll()) {
                AAM platformAAM = new AAM(platform.getPlatformInterworkingInterfaceAddress() + platformAAMSuffixAtInterWorkingInterface, platform.getPlatformInstanceFriendlyName(), platform
                        .getPlatformInstanceId(), platform.getPlatformAAMCertificate(), platform.getComponentCertificates());
                // add the platform AAM entry point to the results
                availableAAMs.put(platformAAM.getAamInstanceId(), platformAAM);
            }
        } else {
            // a PAAM needs to fetch them from core
            availableAAMs = restTemplate.getForEntity(coreAAMAddress + SecurityConstants
                    .AAM_GET_AVAILABLE_AAMS, AvailableAAMsCollection.class).getBody().getAvailableAAMs();
        }
        return availableAAMs;
    }
}
