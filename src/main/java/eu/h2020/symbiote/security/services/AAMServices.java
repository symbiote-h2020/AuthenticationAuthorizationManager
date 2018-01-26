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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
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

    private static Log log = LogFactory.getLog(AAMServices.class);
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final PlatformRepository platformRepository;
    private final ComponentCertificatesRepository componentCertificatesRepository;
    private final String coreInterfaceAddress;
    private final String platformAAMSuffixAtInterWorkingInterface;
    private final String localAAMUrl;
    private final String interworkingInterface;

    @Autowired
    public AAMServices(CertificationAuthorityHelper certificationAuthorityHelper,
                       PlatformRepository platformRepository,
                       ComponentCertificatesRepository componentCertificatesRepository,
                       @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress,
                       @Value("${aam.environment.platformAAMSuffixAtInterWorkingInterface:/paam}") String platformAAMSuffixAtInterWorkingInterface,
                       @Value("${symbIoTe.localaam.url}") String localAAMUrl,
                       @Value("${symbIoTe.interworking.interface.url:MUST_BE_SET_FOR_PAAM}") String interworkingInterface
    ) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.platformRepository = platformRepository;
        this.componentCertificatesRepository = componentCertificatesRepository;
        this.coreInterfaceAddress = coreInterfaceAddress;
        this.platformAAMSuffixAtInterWorkingInterface = platformAAMSuffixAtInterWorkingInterface;
        this.localAAMUrl = localAAMUrl;
        this.interworkingInterface = interworkingInterface;
    }

    @Cacheable(cacheNames = "getAvailableAAMs", key = "#root.method")
    public Map<String, AAM> getAvailableAAMs() throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        return getAvailableAAMs(false);
    }

    @CacheEvict(cacheNames = "getAvailableAAMs", allEntries = true)
    public void deleteFromCacheAvailableAAMs() {
    }

    private Map<String, AAM> getAvailableAAMs(boolean provideInternalURL) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        Map<String, AAM> availableAAMs = new TreeMap<>();
        if (certificationAuthorityHelper.getDeploymentType() == IssuingAuthorityType.CORE) {
            // if Core AAM then we know the available AAMs
            Certificate coreCertificate = new Certificate(certificationAuthorityHelper.getAAMCert());

            // defining how to expose core AAM to the client (end users use CI, components communicate locally)
            String coreAAMAddress = provideInternalURL ? localAAMUrl : coreInterfaceAddress;

            // adding core aam info to the response
            availableAAMs.put(SecurityConstants.CORE_AAM_INSTANCE_ID, new AAM(coreAAMAddress,
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
            try {
                IAAMClient aamClient = new AAMClient(coreInterfaceAddress);
                availableAAMs = aamClient.getAvailableAAMs().getAvailableAAMs();

                String deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
                availableAAMs.get(deploymentId).getComponentCertificates().putAll(fillComponentCertificatesMap());
            } catch (AAMException e) {
                // platform AAM might be disconnected from the core for which we need fallback option
                log.error("Couldn't establish connection with CoreAAM... falling back to local configuration");
                // adding core aam info to the response
                availableAAMs.put(SecurityConstants.CORE_AAM_INSTANCE_ID,
                        new AAM(
                                coreInterfaceAddress,
                                SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                                SecurityConstants.CORE_AAM_INSTANCE_ID,
                                new Certificate(certificationAuthorityHelper.getRootCACert()), new HashMap<>()));
            } finally {
                // handling the local aam address
                String PAAMAddress = provideInternalURL ? localAAMUrl : interworkingInterface;

                // update if it exists
                if (availableAAMs.containsKey(certificationAuthorityHelper.getAAMInstanceIdentifier())) {
                    AAM aam = availableAAMs.get(certificationAuthorityHelper.getAAMInstanceIdentifier());
                    AAM localAAM = new AAM(
                            PAAMAddress,
                            aam.getAamInstanceFriendlyName(),
                            aam.getAamInstanceId(),
                            aam.getAamCACertificate(),
                            aam.getComponentCertificates()
                    );
                    availableAAMs.put(aam.getAamInstanceId(), localAAM);
                } else {
                    // adding local (this) aam info to the response
                    availableAAMs.put(certificationAuthorityHelper.getAAMInstanceIdentifier(),
                            new AAM(
                                    PAAMAddress,
                                    " ",
                                    certificationAuthorityHelper.getAAMInstanceIdentifier(),
                                    new Certificate(certificationAuthorityHelper.getAAMCert()),
                                    fillComponentCertificatesMap()));
                }
            }
        }
        return availableAAMs;
    }

    @Cacheable(cacheNames = "getAAMsInternally", key = "#root.method")
    public Map<String, AAM> getAAMsInternally() throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException {
        return getAvailableAAMs(true);
    }

    @CacheEvict(cacheNames = "getAAMsInternally", allEntries = true)
    public void deleteFromCacheInternalAAMs() {
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

    @CacheEvict(cacheNames = "getComponentCertificate", key = "#componentIdentifier + '@' +#platformIdentifier")
    public void deleteFromCacheComponentCertificate(String componentIdentifier, String platformIdentifier) {

    }
}
