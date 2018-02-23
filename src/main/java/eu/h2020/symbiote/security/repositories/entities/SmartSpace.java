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
    private final String instanceId;
    private String gatewayAddress = "";
    private String siteLocalAddress = "";
    private boolean exposingSiteLocalAddress = false;
    private String instanceFriendlyName = "";
    private Certificate aamCertificate = new Certificate();
    private Map<String, Certificate> componentCertificates = new HashMap<>();
    @DBRef
    private User smartSpaceOwner;

    /**
     * @param instanceId                SymbIoTe-unique smart Space identifier
     * @param gatewayAddress            Address where the SmartSpace is available from the Internet
     * @param siteLocalAddress          Address where the SmartSpace is available from the local site net
     * @param exposingSiteLocalAddress  should siteLocalAddress be exposed
     * @param instanceFriendlyName      a label for the end user to be able to identify the getHomeToken entry point
     * @param smartSpaceOwner           details of the SmartSpace Owner
     */
    public SmartSpace(String instanceId,
                      String gatewayAddress,
                      String siteLocalAddress,
                      boolean exposingSiteLocalAddress,
                      String instanceFriendlyName,
                      Certificate aamCertificate,
                      Map<String, Certificate> componentCertificates,
                      User smartSpaceOwner)
            throws InvalidArgumentsException {
        // TODO use setter and harden the sitelocal depending on bool
        this.instanceId = instanceId;
        setGatewayAddress(gatewayAddress);
        this.siteLocalAddress = siteLocalAddress;
        this.exposingSiteLocalAddress = exposingSiteLocalAddress;
        this.instanceFriendlyName = instanceFriendlyName;
        this.aamCertificate = aamCertificate;
        this.componentCertificates = componentCertificates;
        this.smartSpaceOwner = smartSpaceOwner;
    }

    public String getInstanceId() {
        return instanceId;
    }

    public String getGatewayAddress() {
        return gatewayAddress;
    }

    public void setGatewayAddress(String gatewayAddress) throws InvalidArgumentsException {
        if (!gatewayAddress.startsWith("https")) {
            throw new InvalidArgumentsException("Gateway Address should start with https.");
        }
        this.gatewayAddress = gatewayAddress;
    }

    public String getSiteLocalAddress() {
        return siteLocalAddress;
    }

    public void setSiteLocalAddress(String siteLocalAddress) {
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

    public Certificate getAamCertificate() {
        return aamCertificate;
    }

    public void setAamCertificate(Certificate aamCertificate) {
        this.aamCertificate = aamCertificate;
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
