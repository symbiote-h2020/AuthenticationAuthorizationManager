package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.TokenManager;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Spring service used to provide validation functionality of the AAM.
 *
 * @author Piotr Kicki (PSNC)
 */
@Service
public class ValidationService {
    private final TokenManager tokenManager;

    @Autowired
    public ValidationService(TokenManager tokenManager) {
        this.tokenManager = tokenManager;
    }

    public ValidationStatus checkHomeTokenRevocation(String tokenString) {
        return tokenManager.validate(tokenString);
    }

}
