package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Certificate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;

import java.util.HashMap;
import java.util.Map;

/**
 * SymbIoTe-enabled IoT ssp instance registered in the Core AAM.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class SmartSpace {

    @Id
    private final String sspInstanceId;
    private String sspExternalInterworkingInterfaceAddress = "";
    private String sspInternalInterworkingInterfaceAddress = "";
    private boolean exposedInternalInterworkingInterfaceAddress = false;
    private String sspInstanceFriendlyName = "";
    private Certificate sspAAMCertificate = new Certificate();
    private Map<String, Certificate> componentCertificates = new HashMap<>();
    @DBRef
    private User sspOwner;

    /**
     * @param sspInstanceId                               SymbIoTe-unique ssp identifier
     * @param sspExternalInterworkingInterfaceAddress     Address where the SmartSpace exposes its Interworking Interface
     * @param sspInternalInterworkingInterfaceAddress     Address where the SmartSpace exposes its Interworking Interface inside it's internal network
     * @param exposedInternalInterworkingInterfaceAddress should sspInternalInterworkingInterfaceAddress be exposed
     * @param sspInstanceFriendlyName                     a label for the end user to be able to identify the getHomeToken
     *                                                    endrypoint
     * @param sspOwner                                    details of the SmartSpace Owner
     */
    public SmartSpace(String sspInstanceId,
                      String sspExternalInterworkingInterfaceAddress,
                      String sspInternalInterworkingInterfaceAddress,
                      boolean exposedInternalInterworkingInterfaceAddress,
                      String sspInstanceFriendlyName,
                      Certificate sspAAMCertificate,
                      Map<String, Certificate> componentCertificates,
                      User sspOwner) {
        this.sspInstanceId = sspInstanceId;
        this.sspExternalInterworkingInterfaceAddress = sspExternalInterworkingInterfaceAddress;
        this.sspInternalInterworkingInterfaceAddress = sspInternalInterworkingInterfaceAddress;
        this.exposedInternalInterworkingInterfaceAddress = exposedInternalInterworkingInterfaceAddress;
        this.sspInstanceFriendlyName = sspInstanceFriendlyName;
        this.sspAAMCertificate = sspAAMCertificate;
        this.componentCertificates = componentCertificates;
        this.sspOwner = sspOwner;
    }

    public String getSspInstanceId() {
        return sspInstanceId;
    }

    public String getSspExternalInterworkingInterfaceAddress() {
        return sspExternalInterworkingInterfaceAddress;
    }

    public void setSspExternalInterworkingInterfaceAddress(String sspExternalInterworkingInterfaceAddress) {
        this.sspExternalInterworkingInterfaceAddress = sspExternalInterworkingInterfaceAddress;
    }

    public String getSspInternalInterworkingInterfaceAddress() {
        return sspInternalInterworkingInterfaceAddress;
    }

    public void setSspInternalInterworkingInterfaceAddress(String sspInternalInterworkingInterfaceAddress) {
        this.sspInternalInterworkingInterfaceAddress = sspInternalInterworkingInterfaceAddress;
    }

    public boolean isExposedInternalInterworkingInterfaceAddress() {
        return exposedInternalInterworkingInterfaceAddress;
    }

    public void setExposedInternalInterworkingInterfaceAddress(boolean exposedInternalInterworkingInterfaceAddress) {
        this.exposedInternalInterworkingInterfaceAddress = exposedInternalInterworkingInterfaceAddress;
    }

    public String getSspInstanceFriendlyName() {
        return sspInstanceFriendlyName;
    }

    public void setSspInstanceFriendlyName(String sspInstanceFriendlyName) {
        this.sspInstanceFriendlyName = sspInstanceFriendlyName;
    }

    public Certificate getSspAAMCertificate() {
        return sspAAMCertificate;
    }

    public void setSspAAMCertificate(Certificate sspAAMCertificate) {
        this.sspAAMCertificate = sspAAMCertificate;
    }

    public Map<String, Certificate> getComponentCertificates() {
        return componentCertificates;
    }

    public void setComponentCertificates(Map<String, Certificate> componentCertificates) {
        this.componentCertificates = componentCertificates;
    }

    public User getSspOwner() {
        return sspOwner;
    }

    public void setSspOwner(User sspOwner) {
        this.sspOwner = sspOwner;
    }

}
