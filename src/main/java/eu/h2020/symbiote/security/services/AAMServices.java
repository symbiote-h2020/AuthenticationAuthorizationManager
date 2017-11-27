package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.IAAMClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

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
    private final String coreInterfaceAddress;
    private final String platformAAMSuffixAtInterWorkingInterface;

    @Autowired
    public AAMServices(CertificationAuthorityHelper certificationAuthorityHelper,
                       PlatformRepository platformRepository,
                       ComponentCertificatesRepository componentCertificatesRepository,
                       @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress,
                       @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface:/paam}") String platformAAMSuffixAtInterWorkingInterface) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.platformRepository = platformRepository;
        this.componentCertificatesRepository = componentCertificatesRepository;
        this.coreInterfaceAddress = coreInterfaceAddress;
        this.platformAAMSuffixAtInterWorkingInterface = platformAAMSuffixAtInterWorkingInterface;
    }

    @Cacheable(cacheNames = "getAvailableAAMs", key = "#root.method")
    public Map<String, AAM> getAvailableAAMs() throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            AAMException {
        Map<String, AAM> availableAAMs = new TreeMap<>();
        if (certificationAuthorityHelper.getDeploymentType() == IssuingAuthorityType.CORE) {
            // if Core AAM then we know the available AAMs
            Certificate coreCertificate = new Certificate(certificationAuthorityHelper.getAAMCert());

            // adding core aam info to the response
            availableAAMs.put(SecurityConstants.CORE_AAM_INSTANCE_ID, new AAM(coreInterfaceAddress,
                    SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                    SecurityConstants.CORE_AAM_INSTANCE_ID,
                    coreCertificate, fillComponentCertificatesMap()));

            // registered platforms' AAMs
            for (Platform platform : platformRepository.findAll()) {
                AAM platformAAM = new AAM(platform.getPlatformInterworkingInterfaceAddress() + platformAAMSuffixAtInterWorkingInterface, platform.getPlatformInstanceFriendlyName(), platform
                        .getPlatformInstanceId(), platform.getPlatformAAMCertificate(), platform.getComponentCertificates());
                // add the platform AAM entry point to the results
                availableAAMs.put(platformAAM.getAamInstanceId(), platformAAM);
            }
        } else {
            // a PAAM needs to fetch them from core
            IAAMClient aamClient = new AAMClient(coreInterfaceAddress);
            availableAAMs = aamClient.getAvailableAAMs().getAvailableAAMs();

            String deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
            availableAAMs.get(deploymentId).getComponentCertificates().putAll(fillComponentCertificatesMap());
        }
        return availableAAMs;
    }

    private Map<String, Certificate> fillComponentCertificatesMap() {
        Map<String, Certificate> componentsCertificatesMap = new HashMap<>();
        List<ComponentCertificate> componentCertificatesFromRepository = componentCertificatesRepository.findAll();
        for (ComponentCertificate certificate : componentCertificatesFromRepository) {
            componentsCertificatesMap.put(certificate.getName(), certificate.getCertificate());
        }
        return componentsCertificatesMap;
    }

    @Cacheable(cacheNames = "getComponentCertificate", key = "#componentIdentifier + '@' +#platformIdentifier")
    public String getComponentCertificate(String componentIdentifier, String platformIdentifier) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            AAMException,
            InvalidArgumentsException {

        String deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        // our platform case
        if (platformIdentifier.equals(deploymentId)) {
            if (componentIdentifier.equals(SecurityConstants.AAM_COMPONENT_NAME))
                return certificationAuthorityHelper.getAAMCert();

            if (!componentCertificatesRepository.exists(componentIdentifier))
                throw new InvalidArgumentsException("Component doesn't exist in this platform");
            return componentCertificatesRepository.findOne(componentIdentifier).getCertificate().getCertificateString();
        }
        // not our platform
        Map<String, AAM> availableAAMs = getAvailableAAMs();
        if (availableAAMs.containsKey(platformIdentifier)) {
            AAM aam = availableAAMs.get(platformIdentifier);
            if (componentIdentifier.equals(SecurityConstants.AAM_COMPONENT_NAME)) {
                // AAM cert can be fetched without contacting the platform AAM itself
                return aam.getAamCACertificate().getCertificateString();
            } else {
                IAAMClient aamClient = new AAMClient(aam.getAamAddress());
                return aamClient.getComponentCertificate(componentIdentifier, platformIdentifier);
            }
        }
        throw new AAMException("Selected certificate could not be found/retrieved");
    }
}
