package eu.h2020.symbiote.security.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.EventType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.EventLogRequest;
import eu.h2020.symbiote.security.repositories.ComponentCertificatesRepository;
import eu.h2020.symbiote.security.repositories.PlatformRepository;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.IAnomaliesHelper;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.HashSet;

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
    private final IAnomaliesHelper anomaliesHelper;
    protected ObjectMapper mapper = new ObjectMapper();

    @Value("${rabbit.queue.event}")
    private String anomalyDetectionQueue;
    @Value("${rabbit.routingKey.event}")
    private String anomalyDetectionRoutingKey;

    @Autowired
    public GetTokenService(TokenIssuer tokenIssuer, UserRepository userRepository, ValidationHelper validationHelper, ComponentCertificatesRepository componentCertificateRepository, PlatformRepository platformRepository, CertificationAuthorityHelper certificationAuthorityHelper, RabbitTemplate rabbitTemplate, IAnomaliesHelper anomaliesHelper) {
        this.tokenIssuer = tokenIssuer;
        this.userRepository = userRepository;
        this.validationHelper = validationHelper;
        this.componentCertificateRepository = componentCertificateRepository;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.rabbitTemplate = rabbitTemplate;
        this.anomaliesHelper = anomaliesHelper;
    }

    public Token getForeignToken(Token receivedRemoteHomeToken, String clientCertificate, String aamCertificate) throws
            JWTCreationException,
            ValidationException {
        ValidationStatus validationStatus = validationHelper.validate(receivedRemoteHomeToken.toString(), clientCertificate, aamCertificate, "");
        if (validationStatus != ValidationStatus.VALID) {
            log.error("Validation error occurred: " + validationStatus.name());
            throw new ValidationException("Validation error occurred");
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
            ValidationException, IOException, BlockedUserException {
        // validate request
        JWTClaims claims = JWTEngine.getClaimsFromToken(loginRequest);

        if (claims.getIss() == null || claims.getSub() == null || claims.getIss().isEmpty() || claims.getSub().isEmpty()) {
            throw new InvalidArgumentsException();
        }

        if (anomaliesHelper.isBlocked(claims.getIss(), EventType.ACQUISITION_FAILED))
            throw new BlockedUserException();

        // try to find user
        String sub = claims.getSub();
        User userInDB = userRepository.findOne(claims.getIss());

        User userForToken;
        PublicKey keyForToken;

        // authenticating
        if (claims.getIss().equals(deploymentId)) { // in component use case ISS is platform id
            if (!componentCertificateRepository.exists(sub) //SUB is a componentId
                    || ValidationStatus.VALID != JWTEngine.validateTokenString(loginRequest, componentCertificateRepository.findOne(sub).getCertificate().getX509().getPublicKey())) {
                rabbitTemplate.convertAndSend(anomalyDetectionQueue, mapper.writeValueAsString(
                        new EventLogRequest(claims.getIss(), claims.getSub(), claims.getJti(), deploymentId, EventType.ACQUISITION_FAILED, System.currentTimeMillis(), null, null)));
                throw new WrongCredentialsException();
            }
        } else { // ordinary user/po client
            if (userInDB == null
                    || !userInDB.getClientCertificates().containsKey(sub)
                    || ValidationStatus.VALID != JWTEngine.validateTokenString(loginRequest, userInDB.getClientCertificates().get(sub).getX509().getPublicKey())) {
                rabbitTemplate.convertAndSend(anomalyDetectionQueue, mapper.writeValueAsString(
                        new EventLogRequest(claims.getIss(), claims.getSub(), claims.getJti(), deploymentId, EventType.ACQUISITION_FAILED, System.currentTimeMillis(), null, null)));
                throw new WrongCredentialsException();
            }
        }

        // preparing user and key for token
        if (claims.getIss().equals(deploymentId)) { // component use case ISS is platform id
            // component case (We don't include AAMOwner/PO anymore!)
            userForToken = new User("", "", "", new HashMap<>(), UserRole.NULL, new HashMap<>(), new HashSet<>());
            keyForToken = componentCertificateRepository.findOne(sub).getCertificate().getX509().getPublicKey();
        } else {
            // ordinary user/po client
            userForToken = userInDB;
            keyForToken = userInDB.getClientCertificates().get(sub).getX509().getPublicKey();
        }
        if (anomaliesHelper.isBlocked(userForToken.getUsername(), EventType.ACQUISITION_FAILED)) {
            throw new BlockedUserException();
        }
        return tokenIssuer.getHomeToken(userForToken, sub, keyForToken);
    }

}
