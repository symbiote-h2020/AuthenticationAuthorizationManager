package eu.h2020.symbiote.security.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

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

    public ValidationStatus validate(String tokenString, String clientCertificate, String clientCertificateSigningAAMCertificate, String foreignTokenIssuingAAMCertificate) throws IOException, TimeoutException, WrongCredentialsException {
        ValidationStatus responseStatus = validationHelper.validate(tokenString, clientCertificate, clientCertificateSigningAAMCertificate, foreignTokenIssuingAAMCertificate);

        if(responseStatus != ValidationStatus.VALID){
            rabbitTemplate.convertAndSend(anomalyDetectionQueue, mapper.writeValueAsString(new EventLogRequest(tokenString, this.certificationAuthorityHelper.getAAMInstanceIdentifier(), EventType.VALIDATION_FAILED,System.currentTimeMillis(), null)));
        }
        return responseStatus;
    }
}
