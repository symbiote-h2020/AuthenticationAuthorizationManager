package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.session.AAM;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

/**
 * Access to other services that Core AAM offers.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public interface ICoreServices {
    @GetMapping(value = AAMConstants.AAM_PUBLIC_PATH + AAMConstants.AAM_GET_CA_CERTIFICATE)
    ResponseEntity<String> getCACert();

    @GetMapping(value = AAMConstants.AAM_PUBLIC_PATH + AAMConstants.AAM_GET_AVAILABLE_AAMS, produces = "application/json")
    ResponseEntity<List<AAM>> getAvailableAAMs();
}
