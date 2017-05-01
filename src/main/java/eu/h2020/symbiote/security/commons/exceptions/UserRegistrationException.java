package eu.h2020.symbiote.security.commons.exceptions;

import eu.h2020.symbiote.security.commons.Constants;
import eu.h2020.symbiote.security.commons.CustomAAMException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when user registration over AMQP fails
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class UserRegistrationException extends CustomAAMException {

    private static final long serialVersionUID = Constants.serialVersionUID;
    public final static String errorMessage = "USER_REGISTRATION_ERROR";
    public final static HttpStatus statusCode = HttpStatus.BAD_REQUEST;

    public UserRegistrationException() {
        super(errorMessage);
    }

    public UserRegistrationException(String message) {
        super(message);
    }

    public UserRegistrationException(Throwable cause) {
        super(cause);
    }

    public UserRegistrationException(String message, Throwable cause) {
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
