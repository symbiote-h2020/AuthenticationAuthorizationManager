package eu.h2020.symbiote.security.commons.exceptions;

import eu.h2020.symbiote.security.commons.Constants;
import eu.h2020.symbiote.security.commons.CustomAAMException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when application registration over AMQP fails
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class ApplicationRegistrationException extends CustomAAMException {

    private static final long serialVersionUID = Constants.serialVersionUID;
    private final static String errorMessage = "APP_REGISTRATION_ERROR";
    private final HttpStatus statusCode = HttpStatus.BAD_REQUEST;

    public ApplicationRegistrationException() {
        super(errorMessage);
    }

    public ApplicationRegistrationException(String message) {
        super(message);
    }

    public ApplicationRegistrationException(Throwable cause) {
        super(cause);
    }

    public ApplicationRegistrationException(String message, Throwable cause) {
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
