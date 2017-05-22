package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.session.AAM;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.List;

/**
 * Access to other services that Core AAM offers.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public interface ICoreServices {
    @RequestMapping(value = AAMConstants.AAM_GET_CA_CERTIFICATE, method = RequestMethod.GET)
    ResponseEntity<String> getCACert();

    @RequestMapping(value = AAMConstants.AAM_GET_AVAILABLE_AAMS, method = RequestMethod.GET, produces =
            "application/json")
    ResponseEntity<List<AAM>> getAvailableAAMs();
}
