package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;

/**
 * Used to manage blocked users due anomalies detection.
 *
 * @author Piotr Jakubowski (PSNC)
 */
public interface IAnomaliesHelper {

    /**
     * Used to insert entry connected with detected anomaly.
     *
     * @param handleAnomalyRequest request with data about detected anomaly
     * @return true if entry successfully inserted
     */
    Boolean insertBlockedActionEntry(HandleAnomalyRequest handleAnomalyRequest);

    /**
     * Used to check if user is blocked for specified event type
     *
     * @param username
     * @param eventType
     * @return true if user is blocked for specified event type
     */
    Boolean isBlocked(String username, EventType eventType);
}
