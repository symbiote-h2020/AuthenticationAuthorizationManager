package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.certificate.Certificate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;

/**
 * SymbIoTe-enabled IoT platform instance registered in the Core AAM.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class Platform {

    @Id
    private String platformInstanceId = "";
    private String platformInterworkingInterfaceAddress = "";
    private String platformInstanceFriendlyName = "";
    private Certificate platformAAMCertificate = new Certificate();
    @DBRef
    private User platformOwner;

    /**
     * @param platformInstanceId                   SymbIoTe-unique platform identifier
     * @param platformInterworkingInterfaceAddress Address where the Platform exposes its Interworking Interface
     * @param platformInstanceFriendlyName         a label for the end user to be able to identify the getHomeToken
     *                                             endrypoint
     * @param platformOwner                        details of the Platform Owner
     */
    public Platform(String platformInstanceId,
                    String platformInterworkingInterfaceAddress,
                    String platformInstanceFriendlyName,
                    User platformOwner,
                    Certificate platformAAMCertificate) {
        this.platformInstanceId = platformInstanceId;
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
        this.platformOwner = platformOwner;
        this.platformAAMCertificate = platformAAMCertificate;
    }

    /**
     * @return SymbIoTe-unique platform identifier
     */
    public String getPlatformInstanceId() {
        return platformInstanceId;
    }

    public void setPlatformInstanceId(String platformInstanceId) {
        this.platformInstanceId = platformInstanceId;
    }

    /**
     * @return Address where the Platform exposes its Interworking Interface
     */
    public String getPlatformInterworkingInterfaceAddress() {
        return platformInterworkingInterfaceAddress;
    }

    public void setPlatformInterworkingInterfaceAddress(String platformInterworkingInterfaceAddress) {
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
    }

    public User getPlatformOwner() {
        return platformOwner;
    }

    public void setPlatformOwner(User platformOwner) {
        this.platformOwner = platformOwner;
    }

    /**
     * @return a label for the end user to be able to identify the getHomeToken endrypoint
     */
    public String getPlatformInstanceFriendlyName() {
        return platformInstanceFriendlyName;
    }

    public void setPlatformInstanceFriendlyName(String platformInstanceFriendlyName) {
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
    }

    public Certificate getPlatformAAMCertificate() {
        return platformAAMCertificate;
    }

    public void setPlatformAAMCertificate(Certificate platformAAMCertificate) {
        this.platformAAMCertificate = platformAAMCertificate;
    }
}