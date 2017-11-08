package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IAnomalyHandler;
import eu.h2020.symbiote.security.services.DetectedAnomaliesService;
import io.swagger.annotations.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated with handling detected anomalies.
 *
 * @author Piotr Jakubowski (PSNC)
 */
@Api(value = "/docs/handleAnomaly", description = "Exposes services that allow detected anomaly handling")
@RestController
public class AnomalyController implements IAnomalyHandler {

    private final DetectedAnomaliesService detectedAnomaliesService;
    private Log log = LogFactory.getLog(AnomalyController.class);

    @Autowired
    public AnomalyController(DetectedAnomaliesService detectedAnomaliesService) {
        this.detectedAnomaliesService = detectedAnomaliesService;
    }

    @Override
    @ApiOperation(value = "Allow to report detected anomaly")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Anomaly successfully reported"),
            @ApiResponse(code = 500, message = "Anomaly reporting failed")})
    public ResponseEntity<String> handle(
            @RequestBody
            @ApiParam(name = "Anomaly haandle request", value = "Information needed to block operation that caused anomaly", required = true) HandleAnomalyRequest handleAnomalyRequest) {

        if (detectedAnomaliesService.insertBlockedActionEntry(handleAnomalyRequest))
            return ResponseEntity.status(HttpStatus.OK).body("");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("");

    }

}


