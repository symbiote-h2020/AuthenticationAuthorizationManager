package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Certificate;
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
    private final String smartSpaceInstanceId;
    private String smartSpaceExternalInterworkingInterfaceAddress = "";
    private String smartSpaceInternalInterworkingInterfaceAddress = "";
    private boolean exposedInternalInterworkingInterfaceAddress = false;
    private String smartSpaceInstanceFriendlyName = "";
    private Certificate smartSpaceAAMCertificate = new Certificate();
    private Map<String, Certificate> componentCertificates = new HashMap<>();
    @DBRef
    private User smartSpaceOwner;

    /**
     * @param smartSpaceInstanceId                               SymbIoTe-unique smart Space identifier
     * @param smartSpaceExternalInterworkingInterfaceAddress     Address where the SmartSpace exposes its Interworking Interface
     * @param smartSpaceInternalInterworkingInterfaceAddress     Address where the SmartSpace exposes its Interworking Interface inside it's internal network
     * @param exposedInternalInterworkingInterfaceAddress should smartSpaceInternalInterworkingInterfaceAddress be exposed
     * @param smartSpaceInstanceFriendlyName                     a label for the end user to be able to identify the getHomeToken
     *                                                    endrypoint
     * @param smartSpaceOwner                                    details of the SmartSpace Owner
     */
    public SmartSpace(String smartSpaceInstanceId,
                      String smartSpaceExternalInterworkingInterfaceAddress,
                      String smartSpaceInternalInterworkingInterfaceAddress,
                      boolean exposedInternalInterworkingInterfaceAddress,
                      String smartSpaceInstanceFriendlyName,
                      Certificate smartSpaceAAMCertificate,
                      Map<String, Certificate> componentCertificates,
                      User smartSpaceOwner) {
        this.smartSpaceInstanceId = smartSpaceInstanceId;
        this.smartSpaceExternalInterworkingInterfaceAddress = smartSpaceExternalInterworkingInterfaceAddress;
        this.smartSpaceInternalInterworkingInterfaceAddress = smartSpaceInternalInterworkingInterfaceAddress;
        this.exposedInternalInterworkingInterfaceAddress = exposedInternalInterworkingInterfaceAddress;
        this.smartSpaceInstanceFriendlyName = smartSpaceInstanceFriendlyName;
        this.smartSpaceAAMCertificate = smartSpaceAAMCertificate;
        this.componentCertificates = componentCertificates;
        this.smartSpaceOwner = smartSpaceOwner;
    }

    public String getSmartSpaceInstanceId() {
        return smartSpaceInstanceId;
    }

    public String getSmartSpaceExternalInterworkingInterfaceAddress() {
        return smartSpaceExternalInterworkingInterfaceAddress;
    }

    public void setSmartSpaceExternalInterworkingInterfaceAddress(String smartSpaceExternalInterworkingInterfaceAddress) {
        this.smartSpaceExternalInterworkingInterfaceAddress = smartSpaceExternalInterworkingInterfaceAddress;
    }

    public String getSmartSpaceInternalInterworkingInterfaceAddress() {
        return smartSpaceInternalInterworkingInterfaceAddress;
    }

    public void setSmartSpaceInternalInterworkingInterfaceAddress(String smartSpaceInternalInterworkingInterfaceAddress) {
        this.smartSpaceInternalInterworkingInterfaceAddress = smartSpaceInternalInterworkingInterfaceAddress;
    }

    public boolean isExposedInternalInterworkingInterfaceAddress() {
        return exposedInternalInterworkingInterfaceAddress;
    }

    public void setExposedInternalInterworkingInterfaceAddress(boolean exposedInternalInterworkingInterfaceAddress) {
        this.exposedInternalInterworkingInterfaceAddress = exposedInternalInterworkingInterfaceAddress;
    }

    public String getSmartSpaceInstanceFriendlyName() {
        return smartSpaceInstanceFriendlyName;
    }

    public void setSmartSpaceInstanceFriendlyName(String smartSpaceInstanceFriendlyName) {
        this.smartSpaceInstanceFriendlyName = smartSpaceInstanceFriendlyName;
    }

    public Certificate getSmartSpaceAAMCertificate() {
        return smartSpaceAAMCertificate;
    }

    public void setSmartSpaceAAMCertificate(Certificate smartSpaceAAMCertificate) {
        this.smartSpaceAAMCertificate = smartSpaceAAMCertificate;
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
