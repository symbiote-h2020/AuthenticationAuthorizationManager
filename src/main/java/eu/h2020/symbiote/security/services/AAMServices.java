package eu.h2020.symbiote.security.services;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.IAAMClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.SmartSpaceRepository;
import eu.h2020.symbiote.security.repositories.entities.ComponentCertificate;
import eu.h2020.symbiote.security.repositories.entities.Platform;
import eu.h2020.symbiote.security.repositories.entities.SmartSpace;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;

@Service
public class AAMServices {

    private static Logger log = LoggerFactory.getLogger(AAMServices.class);
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final PlatformRepository platformRepository;
    private final SmartSpaceRepository smartSpaceRepository;
    private final ComponentCertificatesRepository componentCertificatesRepository;

    /**
     * Core Interface address appended by {@link SecurityConstants#AAM_PATH_PREFIX}
     */
    private final String coreAAMAddress;
    /**
     * the address where SymbIoTe components can access the AAM without proxying through CI/II software
     */
    private final String localAAMUrl;
    /**
     * InterworkingInterface address appended by {@link SecurityConstants#AAM_PATH_PREFIX}
     */
    private final String serviceAAMAddress;
    /**
     * Client side entry point to the SmartSpace AAM - available in the SSP intranet (not from the internet)
     */
    private final String sspIntranetAAMAddress;

    /**
     * @param certificationAuthorityHelper    autowired
     * @param platformRepository              autowired
     * @param smartSpaceRepository            autowired
     * @param componentCertificatesRepository autowired
     * @param localAAMUrl                     (property) the address where SymbIoTe components can access the AAM without proxying through CI/II software
     * @param coreInterfaceAddress            (property) needed to resolve the CoreAAM Internet visible address
     * @param interworkingInterface           (property) needed to resolver the service (Platform/Enabler/SmartSpace) AAM Internet visible address
     * @param siteLocalAddress                (property) Client side entry point to the SmartSpace AAM - available in the SSP intranet (not from the Internet)
     */
    @Autowired
    public AAMServices(CertificationAuthorityHelper certificationAuthorityHelper,
                       PlatformRepository platformRepository,
                       SmartSpaceRepository smartSpaceRepository,
                       ComponentCertificatesRepository componentCertificatesRepository,
                       @Value("${symbIoTe.localaam.url}") String localAAMUrl,
                       @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress,
                       @Value("${symbIoTe.interworking.interface.url:MUST_BE_SET_FOR_PAAM_AND_SAAM}") String interworkingInterface,
                       @Value("${symbIoTe.siteLocal.url:MUST_BE_SET_FOR_SAAM}") String siteLocalAddress
    ) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.platformRepository = platformRepository;
        this.smartSpaceRepository = smartSpaceRepository;
        this.componentCertificatesRepository = componentCertificatesRepository;
        this.coreAAMAddress = coreInterfaceAddress + SecurityConstants.AAM_PATH_PREFIX;
        this.localAAMUrl = localAAMUrl;
        this.serviceAAMAddress = interworkingInterface + SecurityConstants.AAM_PATH_PREFIX;
        this.sspIntranetAAMAddress = siteLocalAddress + SecurityConstants.AAM_PATH_PREFIX;
    }

    @Cacheable(cacheNames = "getAvailableAAMs", key = "#root.method")
    public Map<String, AAM> getAvailableAAMs() throws
            IOException,
            CertificateException,
            AAMException {
        return getAvailableAAMs(false);
    }

    @CacheEvict(cacheNames = "getAvailableAAMs", allEntries = true)
    public void invalidateAvailableAAMsCache() {
        //function invalidating cache thanks to proper annotation
    }

    private Map<String, AAM> getAvailableAAMs(boolean provideInternalURL) throws
            IOException,
            CertificateException, AAMException {
        Map<String, AAM> availableAAMs = new TreeMap<>();
        switch (certificationAuthorityHelper.getDeploymentType()) {
            case CORE:
                // if Core AAM then we know the available AAMs
                Certificate coreCertificate = new Certificate(certificationAuthorityHelper.getAAMCert());

                // defining how to expose core AAM to the client (end users use CI, components communicate locally)
                String coreAAMAddress = provideInternalURL ? localAAMUrl : this.coreAAMAddress;

                // adding core aam info to the response
                availableAAMs.put(SecurityConstants.CORE_AAM_INSTANCE_ID,
                        new AAM(coreAAMAddress,
                                "",
                                SecurityConstants.CORE_AAM_INSTANCE_ID,
                                SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                                coreCertificate,
                                fillComponentCertificatesMap()));

                // registered platforms' AAMs
                for (Platform platform : platformRepository.findAll()) {
                    AAM platformAAM = new AAM(platform.getPlatformInterworkingInterfaceAddress() + SecurityConstants.AAM_PATH_PREFIX,
                            "",
                            platform.getPlatformInstanceId(),
                            platform.getPlatformInstanceFriendlyName(),
                            platform.getPlatformAAMCertificate(),
                            platform.getComponentCertificates());
                    // add the platform AAM entry point to the results
                    availableAAMs.put(platformAAM.getAamInstanceId(), platformAAM);
                }
                // registered smart Spaces' AAMs
                for (SmartSpace smartSpace : smartSpaceRepository.findAll()) {
                    String siteLocalAddress = smartSpace.isExposingSiteLocalAddress() ? smartSpace.getSiteLocalAddress() + SecurityConstants.AAM_PATH_PREFIX : "";
                    AAM smartSpaceAAM = new AAM(smartSpace.getExternalAddress() + SecurityConstants.AAM_PATH_PREFIX,
                            siteLocalAddress,
                            smartSpace.getInstanceIdentifier(),
                            smartSpace.getInstanceFriendlyName(),
                            smartSpace.getLocalCertificationAuthorityCertificate(),
                            smartSpace.getComponentCertificates());
                    // add the smart Space AAM entry point to the results
                    availableAAMs.put(smartSpaceAAM.getAamInstanceId(), smartSpaceAAM);
                }
                break;
            case PLATFORM:
                // a PAAM/SAAM needs to fetch them from core
                availableAAMs = getAAMsFromCore(availableAAMs);

                // handling the local (deployment internal) aam address
                String availableAtAddress = provideInternalURL ? localAAMUrl : serviceAAMAddress;

                // update if it exists
                if (availableAAMs.containsKey(certificationAuthorityHelper.getAAMInstanceIdentifier())) {
                    AAM aam = availableAAMs.get(certificationAuthorityHelper.getAAMInstanceIdentifier());
                    AAM localAAM = new AAM(
                            availableAtAddress,
                            "",
                            aam.getAamInstanceId(),
                            aam.getAamInstanceFriendlyName(),
                            aam.getAamCACertificate(),
                            fillComponentCertificatesMap()
                    );
                    availableAAMs.put(aam.getAamInstanceId(), localAAM);
                } else {
                    // adding local (this) aam info to the response
                    availableAAMs.put(certificationAuthorityHelper.getAAMInstanceIdentifier(),
                            new AAM(availableAtAddress,
                                    "", // available only in SAAM
                                    certificationAuthorityHelper.getAAMInstanceIdentifier(),
                                    " ",
                                    new Certificate(certificationAuthorityHelper.getAAMCert()),
                                    fillComponentCertificatesMap()));
                }
                break;
            case SMART_SPACE:
                // a PAAM/SAAM needs to fetch them from core
                availableAAMs = getAAMsFromCore(availableAAMs);

                // handling the local (deployment internal) aam address
                availableAtAddress = provideInternalURL ? localAAMUrl : serviceAAMAddress;

                // update if it exists
                if (availableAAMs.containsKey(certificationAuthorityHelper.getAAMInstanceIdentifier())) {
                    AAM aam = availableAAMs.get(certificationAuthorityHelper.getAAMInstanceIdentifier());
                    AAM localAAM = new AAM(
                            availableAtAddress,
                            sspIntranetAAMAddress,
                            aam.getAamInstanceId(),
                            aam.getAamInstanceFriendlyName(),
                            aam.getAamCACertificate(),
                            fillComponentCertificatesMap()
                    );
                    availableAAMs.put(aam.getAamInstanceId(), localAAM);
                } else {
                    // adding local (this) aam info to the response
                    availableAAMs.put(certificationAuthorityHelper.getAAMInstanceIdentifier(),
                            new AAM(availableAtAddress,
                                    sspIntranetAAMAddress,
                                    certificationAuthorityHelper.getAAMInstanceIdentifier(),
                                    " ",
                                    new Certificate(certificationAuthorityHelper.getAAMCert()),
                                    fillComponentCertificatesMap()));
                }
                break;
            case NULL:
                break;
        }
        return availableAAMs;
    }

    private Map<String, AAM> getAAMsFromCore(Map<String, AAM> availableAAMs) throws
            CertificateException,
            IOException,
            AAMException {
        try {
            IAAMClient aamClient = new AAMClient(coreAAMAddress);
            availableAAMs = aamClient.getAvailableAAMs().getAvailableAAMs();
        } catch (AAMException e) {
            // service AAM might be disconnected from the core for which we need fallback option
            log.error("Couldn't establish connection with CoreAAM... falling back to local configuration");
            // adding core aam info to the response
            availableAAMs.put(SecurityConstants.CORE_AAM_INSTANCE_ID,
                    new AAM(
                            coreAAMAddress,
                            "",
                            SecurityConstants.CORE_AAM_INSTANCE_ID,
                            SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                            new Certificate(certificationAuthorityHelper.getRootCACert()),
                            new HashMap<>()));
            return availableAAMs;
        }
        String deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        if (!availableAAMs.containsKey(deploymentId)) {
            log.error("The core AAM does not know about us... ");
            throw new AAMException("The core AAM does not know about us... ");
        }
        availableAAMs.get(deploymentId).getComponentCertificates().putAll(fillComponentCertificatesMap());
        return availableAAMs;
    }

    @Cacheable(cacheNames = "getAAMsInternally", key = "#root.method")
    public Map<String, AAM> getAAMsInternally() throws
            CertificateException,
            IOException,
            AAMException {
        return getAvailableAAMs(true);
    }

    @CacheEvict(cacheNames = "getAAMsInternally", allEntries = true)
    public void invalidateInternalAAMsCache() {
        //function invalidating cache thanks to proper annotation
    }

    private Map<String, Certificate> fillComponentCertificatesMap() {
        Map<String, Certificate> componentsCertificatesMap = new HashMap<>();
        for (ComponentCertificate certificate : componentCertificatesRepository.findAll()) {
            componentsCertificatesMap.put(certificate.getName(), certificate.getCertificate());
        }
        return componentsCertificatesMap;
    }

    @Cacheable(cacheNames = "getComponentCertificate", key = "#componentIdentifier + '@' +#serviceIdentifier")
    public String getComponentCertificate(String componentIdentifier,
                                          String serviceIdentifier) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            IOException,
            AAMException,
            InvalidArgumentsException {

        String deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        // our service case
        if (serviceIdentifier.equals(deploymentId)) {
            if (componentIdentifier.equals(SecurityConstants.AAM_COMPONENT_NAME))
                return certificationAuthorityHelper.getAAMCert();

            if (!componentCertificatesRepository.existsById(componentIdentifier))
                throw new InvalidArgumentsException(InvalidArgumentsException.COMPONENT_NOT_EXIST);
            return componentCertificatesRepository.findById(componentIdentifier).get().getCertificate().getCertificateString();
        }
        // not our service
        Map<String, AAM> availableAAMs = getAvailableAAMs();

        //check if received Core cert is the same as this in our keystore
        try {
            if (!availableAAMs.containsKey(SecurityConstants.CORE_AAM_INSTANCE_ID)
                    || !availableAAMs.get(SecurityConstants.CORE_AAM_INSTANCE_ID).getAamCACertificate().getX509().equals(certificationAuthorityHelper.getRootCACertificate())) {
                throw new AAMException(AAMException.CORE_AAM_IS_NOT_TRUSTED);
            }
        } catch (CertificateException ce) {
            // we may fail to parse the request
            throw new AAMException(AAMException.CORE_AAM_IS_NOT_TRUSTED);
        }
        if (availableAAMs.containsKey(serviceIdentifier)) {
            AAM aam = availableAAMs.get(serviceIdentifier);
            if (componentIdentifier.equals(SecurityConstants.AAM_COMPONENT_NAME)) {
                // AAM cert can be fetched without contacting the service AAM itself
                String remoteAAMCertString = aam.getAamCACertificate().getCertificateString();

                if (!certificationAuthorityHelper.isServiceCertificateChainTrusted(remoteAAMCertString))
                    throw new AAMException(AAMException.REMOTE_AAM_CERTIFICATE_IS_NOT_TRUSTED);

                return remoteAAMCertString;
            } else {
                IAAMClient aamClient = new AAMClient(aam.getAamAddress());
                String remoteAAMComponentCertString = aamClient.getComponentCertificate(componentIdentifier, serviceIdentifier);
                if (!CryptoHelper.isClientCertificateChainTrusted(certificationAuthorityHelper.getRootCACert(),
                        aam.getAamCACertificate().getCertificateString(),
                        remoteAAMComponentCertString))
                    throw new AAMException(AAMException.REMOTE_AAMS_COMPONENT_CERTIFICATE_IS_NOT_TRUSTED);
                return remoteAAMComponentCertString;
            }
        }
        throw new AAMException(AAMException.SELECTED_CERTIFICATE_NOT_FOUND);
    }

    @CacheEvict(cacheNames = "getComponentCertificate", key = "#componentIdentifier + '@' +#serviceIdentifier")
    public void invalidateComponentCertificateCache(String componentIdentifier,
                                                    String serviceIdentifier) {
        //function invalidating cache thanks to proper annotation
    }
}
