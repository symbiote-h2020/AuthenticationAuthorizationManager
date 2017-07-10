package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.certificate.Certificate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;

/**
 * SymbIoTe-enabled IoT platform instance registered in the Core AAM.
 *
 * @author Mikołaj Dobski (PSNC)
 */
@Getter @Setter @AllArgsConstructor
public class Platform {

    @Id
    private String platformInstanceId = "";
    private String platformInterworkingInterfaceAddress = "";
    private String platformInstanceFriendlyName = "";
    @DBRef
    private User platformOwner;

    private Certificate platformAAMCertificate = new Certificate();
    // TODO R3 once we implement CSR, the platform should also contain the certificate issued for its PAAM


}
