package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.communication.payloads.HandleAnomalyRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IAnomalyHandler;
import io.swagger.annotations.*;
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

    @Autowired
    public AnomalyController() { }

    @Override
    @ApiOperation(value = "Allow to report detected anomaly")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Anomaly reported")})
    public ResponseEntity<String> handle(
            @RequestBody
            @ApiParam(name = "Anomaly haandle request", value = "Information needed to block operation that caused anomaly", required = true) HandleAnomalyRequest handleAnomalyRequest) {

        return ResponseEntity.status(HttpStatus.OK).body("true");
    }

}


