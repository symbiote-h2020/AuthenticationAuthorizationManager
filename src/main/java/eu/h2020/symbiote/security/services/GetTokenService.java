package eu.h2020.symbiote.security.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.handler.IAnomalyListenerSecurity;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Optional;

/**
 * Spring service used to provide token related functionality of the AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class GetTokenService {
    private static Log log = LogFactory.getLog(GetTokenService.class);

    private final TokenIssuer tokenIssuer;
    private final ComponentCertificatesRepository componentCertificateRepository;
    private final UserRepository userRepository;
    private final ValidationHelper validationHelper;
    private final String deploymentId;
    private final RabbitTemplate rabbitTemplate;
    private final IAnomalyListenerSecurity anomaliesHelper;
    private final JavaMailSenderImpl emailSender;
    private final ObjectMapper mapper = new ObjectMapper();
    private final String anomalyDetectionQueue;


    @Autowired
    public GetTokenService(TokenIssuer tokenIssuer,
                           UserRepository userRepository,
                           ValidationHelper validationHelper,
                           ComponentCertificatesRepository componentCertificateRepository,
                           CertificationAuthorityHelper certificationAuthorityHelper,
                           RabbitTemplate rabbitTemplate,
                           IAnomalyListenerSecurity anomaliesHelper,
                           @Qualifier("getJavaMailSender") JavaMailSenderImpl emailSender,
                           @Value("${rabbit.queue.event}") String anomalyDetectionQueue) {
        this.tokenIssuer = tokenIssuer;
        this.userRepository = userRepository;
        this.validationHelper = validationHelper;
        this.componentCertificateRepository = componentCertificateRepository;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.rabbitTemplate = rabbitTemplate;
        this.anomaliesHelper = anomaliesHelper;
        this.emailSender = emailSender;
        this.anomalyDetectionQueue = anomalyDetectionQueue;
    }

    public Token getForeignToken(Token receivedRemoteHomeToken, String clientCertificate, String aamCertificate) throws
            JWTCreationException,
            ValidationException {
        ValidationStatus validationStatus = validationHelper.validate(receivedRemoteHomeToken.toString(), clientCertificate, aamCertificate, "");
        if (validationStatus != ValidationStatus.VALID) {
            log.error("Validation error occurred: " + validationStatus.name());
            throw new ValidationException(ValidationException.VALIDATION_ERROR_OCCURRED);
        }
        return tokenIssuer.getForeignToken(receivedRemoteHomeToken);
    }

    public Token getGuestToken() throws JWTCreationException {
        return tokenIssuer.getGuestToken();
    }

    public Token getHomeToken(String loginRequest) throws
            MalformedJWTException,
            InvalidArgumentsException,
            JWTCreationException,
            WrongCredentialsException,
            CertificateException,
            ValidationException,
            BlockedUserException {
        // validate request
        JWTClaims claims = JWTEngine.getClaimsFromToken(loginRequest);

        if (claims.getIss() == null || claims.getSub() == null || claims.getIss().isEmpty() || claims.getSub().isEmpty()) {
            throw new InvalidArgumentsException();
        }

        // try to find user
        String sub = claims.getSub();
        User userInDB = userRepository.findOne(claims.getIss());

        if (anomaliesHelper.isBlocked(//check if action was blocked
                Optional.of(claims.getIss()),
                Optional.of(claims.getSub()),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                EventType.ACQUISITION_FAILED)
                || anomaliesHelper.isBlocked(//check if user was blocked
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.of(claims.getSub()),
                Optional.of(claims.getIss()),
                EventType.ACQUISITION_FAILED)) {
            if (userInDB != null && !userInDB.getRecoveryMail().isEmpty()) {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setFrom(deploymentId);
                message.setTo(userInDB.getRecoveryMail());
                message.setSubject("Your action was blocked");
                message.setText("Number of wrong authorization attempts was detected, client " + claims.getSub() + " was blocked for 60s");
                emailSender.send(message);
            }
            throw new BlockedUserException();
        }

        User userForToken;
        PublicKey keyForToken;

        // authenticating
        if (claims.getIss().equals(deploymentId)) { // in component use case ISS is platform id

            if (!componentCertificateRepository.exists(sub) //SUB is a componentId
                    || ValidationStatus.VALID != JWTEngine.validateTokenString(loginRequest, componentCertificateRepository.findOne(sub).getCertificate().getX509().getPublicKey())) {
                try {
                    rabbitTemplate.convertAndSend(anomalyDetectionQueue, mapper.writeValueAsString(
                            new EventLogRequest(
                                    "",
                                    "",
                                    "",
                                    claims.getSub(),
                                    claims.getIss(),
                                    EventType.ACQUISITION_FAILED,
                                    System.currentTimeMillis(),
                                    null,
                                    null)).getBytes());
                    log.info("New event sent to ADM: " + claims.getIss() + " " + claims.getSub() + " " + claims.getJti());
                } catch (JsonProcessingException e) {
                    log.error(e);
                }
                throw new WrongCredentialsException();
            }
        } else { // ordinary user/po client
            if (userInDB != null && userInDB.getStatus() != AccountStatus.ACTIVE)
                throw new BlockedUserException();
            if (userInDB == null
                    || !userInDB.getClientCertificates().containsKey(sub)
                    || ValidationStatus.VALID != JWTEngine.validateTokenString(loginRequest, userInDB.getClientCertificates().get(sub).getX509().getPublicKey())) {
                try {
                    rabbitTemplate.convertAndSend(anomalyDetectionQueue, mapper.writeValueAsString(
                            new EventLogRequest(claims.getIss(), claims.getSub(), "", "", deploymentId, EventType.ACQUISITION_FAILED, System.currentTimeMillis(), null, null)).getBytes());
                    log.info("New event sent to ADM: " + claims.getIss() + " " + claims.getSub());
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                }
                throw new WrongCredentialsException();
            }
        }

        // preparing user and key for token
        if (claims.getIss().equals(deploymentId)) { // component use case ISS is platform id
            // component case (We don't include AAMOwner/PO anymore!)
            userForToken = new User("", "", "", new HashMap<>(), UserRole.NULL, AccountStatus.ACTIVE, new HashMap<>(), new HashSet<>(), true, false);
            keyForToken = componentCertificateRepository.findOne(sub).getCertificate().getX509().getPublicKey();
        } else {
            // ordinary user/po client
            userForToken = userInDB;
            keyForToken = userInDB.getClientCertificates().get(sub).getX509().getPublicKey();
        }
        return tokenIssuer.getHomeToken(userForToken, sub, keyForToken);
    }

}
