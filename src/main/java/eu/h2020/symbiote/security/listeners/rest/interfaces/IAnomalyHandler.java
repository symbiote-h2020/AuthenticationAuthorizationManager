package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes services that allow detected anomaly handling.
 *
 * @author Piotr Jakubowski (PSNC)
 */
public interface IAnomalyHandler {

    /**
     * Exposes services that allow detected anomaly handling.
     *
     * @param handleAnomalyRequest required to report anomaly.
     * @return ResponseEntity<String> where as header HTTP status is sent and in body true/false.
     */
    @PostMapping(value = SecurityConstants.ANOMALY_DETECTION_MESSAGE, consumes = "application/json")
    ResponseEntity<String> handle(@RequestBody HandleAnomalyRequest handleAnomalyRequest);

}
