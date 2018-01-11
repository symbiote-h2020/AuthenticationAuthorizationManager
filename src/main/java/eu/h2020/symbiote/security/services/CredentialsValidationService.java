package eu.h2020.symbiote.security.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Spring service used to provide validation functionality of the AAM.
 *
 * @author Piotr Kicki (PSNC)
 */
@Service
public class CredentialsValidationService {

    @Value("${rabbit.queue.event}")
    private String anomalyDetectionQueue;
    @Value("${rabbit.routingKey.event}")
    private String anomalyDetectionRoutingKey;

    private static Log log = LogFactory.getLog(CredentialsValidationService.class);
    private final ValidationHelper validationHelper;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final RabbitTemplate rabbitTemplate;
    protected ObjectMapper mapper = new ObjectMapper();

    @Autowired
    public CredentialsValidationService(ValidationHelper validationHelper, CertificationAuthorityHelper certificationAuthorityHelper, RabbitTemplate rabbitTemplate) {
        this.validationHelper = validationHelper;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.rabbitTemplate = rabbitTemplate;
    }

    public ValidationStatus validate(String tokenString, String clientCertificate, String clientCertificateSigningAAMCertificate, String foreignTokenIssuingAAMCertificate) {
        ValidationStatus responseStatus = validationHelper.validate(tokenString, clientCertificate, clientCertificateSigningAAMCertificate, foreignTokenIssuingAAMCertificate);

        if(responseStatus != ValidationStatus.VALID){
            try {
                rabbitTemplate.convertAndSend(anomalyDetectionQueue, mapper.writeValueAsString(new EventLogRequest(tokenString, this.certificationAuthorityHelper.getAAMInstanceIdentifier(), EventType.VALIDATION_FAILED, System.currentTimeMillis(), null)).getBytes());
            } catch (JsonProcessingException e) {
                log.error("Couldn't send information about security issue to ADM.");
                return responseStatus;
            }
        }
        return responseStatus;
    }
}
