package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IValidateClientCertificate;
import eu.h2020.symbiote.security.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @JT please review
 */
@RestController
public class ValidateClientCertificate implements IValidateClientCertificate {

    private final UserRepository userRepository;

    @Autowired
    public ValidateClientCertificate(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    /**
     * @param foreignToken - Foreign token which validity is to be confirmed
     * @return Validation status of operation
     */
    public ResponseEntity<ValidationStatus> confirmClientCertificateValidity(@RequestBody String foreignToken) throws MalformedJWTException {
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromToken(foreignToken);
        String sub = claimsFromToken.getSub();

        /*
        * TODO -> Implement
        */
        String clientID = sub.split("@")[1];
        //  User Repository is EMPTY TODO : fix
        if (!userRepository.exists(clientID)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ValidationStatus.EXPIRED_TOKEN);
        }
        return ResponseEntity.ok(ValidationStatus.VALID);
    }
}
