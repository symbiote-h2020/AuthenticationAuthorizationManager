package eu.h2020.symbiote.commons.exceptions;

import org.springframework.http.HttpStatus;
import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.CustomAAMException;

/**
 * Custom exception thrown when application credentials are not present in DB during unregistration procedure in {@link eu.h2020.symbiote.services.ApplicationRegistrationService}
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class NotExistingApplicationException extends CustomAAMException {

    private static final long serialVersionUID = Constants.serialVersionUID;

    private final HttpStatus statusCode = HttpStatus.BAD_REQUEST;
    private final static String errorMessage = "APP_NOT_REGISTERED_IN_DB";

    public NotExistingApplicationException() {
        super(errorMessage);
    }

    public NotExistingApplicationException(String message) {
        super(message);
    }

    public NotExistingApplicationException(Throwable cause) {
        super(cause);
    }

    public NotExistingApplicationException(String message, Throwable cause) {
        super(message, cause);
    }

    @Override
    public HttpStatus getStatusCode() {
        return statusCode;
    }

    @Override
    public String getErrorMessage() {
        return errorMessage;
    }
}