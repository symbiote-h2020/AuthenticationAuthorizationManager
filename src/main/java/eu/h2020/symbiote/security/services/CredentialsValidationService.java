package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Spring service used to provide validation functionality of the AAM.
 *
 * @author Piotr Kicki (PSNC)
 */
@Service
public class CredentialsValidationService {
    private final ValidationHelper validationHelper;

    @Autowired
    public CredentialsValidationService(ValidationHelper validationHelper) {
        this.validationHelper = validationHelper;
    }

    public ValidationStatus validate(String tokenString, String certificateString) {
        return validationHelper.validate(tokenString, certificateString);
    }
}
