package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.interfaces.IAAMServices;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.repositories.UserRepository;
import eu.h2020.symbiote.security.repositories.entities.User;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.security.cert.CertificateException;
import java.util.Map;

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
    private UserRepository userRepository;
    private final static String AAM_NOT_FOUND = "Couldn't find AAM related with the given token";
    private final static String ISSUING_HOME_TOKEN_ERROR = "Someone tried issuing a foreign token using a home token";
    private final TokenIssuer tokenIssuer;
    private IAAMServices coreServicesController;
    private ValidationHelper validationHelper;
    private String deploymentId = "";
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;
    private Log log = LogFactory.getLog(GetTokenService.class);
    @Value("${symbiote.coreaam.url:localhost}")
    private String coreAAMAddress = "";

    @Autowired
    public GetTokenService(TokenIssuer tokenIssuer, UserRepository userRepository, CertificationAuthorityHelper
            certificationAuthorityHelper, IAAMServices coreServices, ValidationHelper validationHelper) {
        this.tokenIssuer = tokenIssuer;
        this.userRepository = userRepository;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.coreServicesController = coreServices;
        this.validationHelper = validationHelper;

    }

    public Token getForeignToken(Token receivedToken, String certificate) throws JWTCreationException, ValidationException {

        if (receivedToken.getClaims().getIssuer().equals(deploymentId)) {
            log.error(ISSUING_HOME_TOKEN_ERROR);
            throw new ValidationException(ISSUING_HOME_TOKEN_ERROR);
        } else {
            Map<String, AAM> availableAAMs;
            if (deploymentType == IssuingAuthorityType.CORE) {
                // if Core AAM then we know the available AAMs
                availableAAMs = coreServicesController.getAvailableAAMs().getBody().getAvailableAAMs();
            } else {
                // a PAAM needs to fetch them from core
                RestTemplate restTemplate = new RestTemplate();
                availableAAMs = restTemplate.exchange(coreAAMAddress + SecurityConstants
                        .AAM_GET_AVAILABLE_AAMS, HttpMethod.GET, null, new ParameterizedTypeReference<Map<String,
                        AAM>>() {
                }).getBody();
            }
            AAM remoteAAM = availableAAMs.get(receivedToken.getClaims().getIssuer());
            if (remoteAAM == null) {
                log.error(AAM_NOT_FOUND);
                throw new ValidationException(AAM_NOT_FOUND);
            }

            MultiValueMap<String, String> headersMap = new LinkedMultiValueMap<>();
            headersMap.add(SecurityConstants.TOKEN_HEADER_NAME, receivedToken.toString());
            HttpEntity<String> request = new HttpEntity<>(null, headersMap);
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<ValidationStatus> status = restTemplate.postForEntity(remoteAAM.getAamAddress() +
                    SecurityConstants.AAM_VALIDATE, request, ValidationStatus.class);

            ValidationStatus validationStatus = status.getBody();
            if (validationStatus != ValidationStatus.VALID) {
                log.error(AAM_NOT_FOUND);
                throw new ValidationException(AAM_NOT_FOUND);
            }
            validationStatus = validationHelper.validate(receivedToken.toString(), certificate);
            if (validationStatus != ValidationStatus.VALID) {
                log.error("Validation error occured: " + validationStatus.name());
                throw new ValidationException("Validation error occured");
            }
        }
        return tokenIssuer.getForeignToken(receivedToken);
    }

    public Token getGuestToken() throws JWTCreationException {
        return tokenIssuer.getGuestToken();
    }

    public Token getHomeToken(String loginRequest) throws MalformedJWTException, MissingArgumentsException, JWTCreationException, WrongCredentialsException, CertificateException, ValidationException {
        // validate request
        JWTClaims claims = JWTEngine.getClaimsFromToken(loginRequest);

        if (claims.getIss() == null || claims.getSub() == null || claims.getIss().isEmpty() || claims.getSub().isEmpty()) {
            throw new MissingArgumentsException();
        }
        // try to find user
        User userInDB = userRepository.findOne(claims.getIss());

        // verify user credentials
        if (userInDB == null
                || userInDB.getClientCertificates().get(claims.getSub()) == null
                || JWTEngine.validateTokenString(loginRequest, userInDB.getClientCertificates().get(claims.getSub()).getX509().getPublicKey()) != ValidationStatus.VALID) {
            throw new WrongCredentialsException();
        }
        return tokenIssuer.getHomeToken(userInDB, claims.getSub());
    }
}
