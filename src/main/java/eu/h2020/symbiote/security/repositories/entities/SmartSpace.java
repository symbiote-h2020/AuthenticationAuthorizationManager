package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;

import java.util.HashMap;
import java.util.Map;

/**
 * SymbIoTe-enabled IoT Smart Space instance registered in the Core AAM.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class SmartSpace {

    @Id
    private final String instanceIdentifier;
    private String externalAddress = "";
    private String siteLocalAddress = "";
    private boolean exposingSiteLocalAddress = false;
    private String instanceFriendlyName = "";
    private Certificate localCertificationAuthorityCertificate = new Certificate();
    private Map<String, Certificate> componentCertificates = new HashMap<>();
    @DBRef
    private User smartSpaceOwner;

    /**
     * @param instanceIdentifier                     SymbIoTe-unique smart Space identifier
     * @param instanceFriendlyName                   a label for the end user to be able to identify the getHomeToken entry point
     * @param externalAddress                        address where the AAM is available from the Internet e.g. the Core, Platforms and SmartSpaces' gateways
     * @param exposingSiteLocalAddress               should siteLocalAddress be exposed
     * @param siteLocalAddress                       address where the AAM is available for clients residing in the same network that the server (e.g. local WiFi of a smart space)
     * @param localCertificationAuthorityCertificate the Certification Authority certificate that this AAM uses to sign its clients certificates and tokens
     * @param smartSpaceOwner                        details of the SmartSpace Owner
     */
    public SmartSpace(String instanceIdentifier,
                      String instanceFriendlyName,
                      String externalAddress,
                      boolean exposingSiteLocalAddress,
                      String siteLocalAddress,
                      Certificate localCertificationAuthorityCertificate,
                      Map<String, Certificate> componentCertificates,
                      User smartSpaceOwner)
            throws InvalidArgumentsException {
        this.instanceIdentifier = instanceIdentifier;
        this.exposingSiteLocalAddress = exposingSiteLocalAddress;
        setExternalAddress(externalAddress);
        setSiteLocalAddress(siteLocalAddress);
        this.instanceFriendlyName = instanceFriendlyName;
        this.localCertificationAuthorityCertificate = localCertificationAuthorityCertificate;
        this.componentCertificates = componentCertificates;
        this.smartSpaceOwner = smartSpaceOwner;
    }


    public String getInstanceIdentifier() {
        return instanceIdentifier;
    }

    public String getExternalAddress() {
        return externalAddress;
    }

    public void setExternalAddress(String externalAddress) throws InvalidArgumentsException {
        if (!externalAddress.isEmpty()
                && !externalAddress.startsWith("https://")) {
            throw new InvalidArgumentsException(InvalidArgumentsException.EXTERNAL_ADDRESS_MUST_START_WITH_HTTPS);
        }
        this.externalAddress = externalAddress;
    }

    public String getSiteLocalAddress() {
        return siteLocalAddress;
    }

    public void setSiteLocalAddress(String siteLocalAddress) throws
            InvalidArgumentsException {
        if (this.exposingSiteLocalAddress
                && (siteLocalAddress == null || siteLocalAddress.isEmpty()))
            throw new InvalidArgumentsException("Exposed siteLocalAddress should not be empty.");
        this.siteLocalAddress = siteLocalAddress;

    }

    public boolean isExposingSiteLocalAddress() {
        return exposingSiteLocalAddress;
    }

    public void setExposingSiteLocalAddress(boolean exposingSiteLocalAddress) {
        this.exposingSiteLocalAddress = exposingSiteLocalAddress;
    }

    public String getInstanceFriendlyName() {
        return instanceFriendlyName;
    }

    public void setInstanceFriendlyName(String instanceFriendlyName) {
        this.instanceFriendlyName = instanceFriendlyName;
    }

    public Certificate getLocalCertificationAuthorityCertificate() {
        return localCertificationAuthorityCertificate;
    }

    public void setLocalCertificationAuthorityCertificate(Certificate localCertificationAuthorityCertificate) {
        this.localCertificationAuthorityCertificate = localCertificationAuthorityCertificate;
    }

    public Map<String, Certificate> getComponentCertificates() {
        return componentCertificates;
    }

    public void setComponentCertificates(Map<String, Certificate> componentCertificates) {
        this.componentCertificates = componentCertificates;
    }

    public User getSmartSpaceOwner() {
        return smartSpaceOwner;
    }

    public void setSmartSpaceOwner(User smartSpaceOwner) {
        this.smartSpaceOwner = smartSpaceOwner;
    }

}
