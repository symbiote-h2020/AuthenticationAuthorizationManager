package eu.h2020.symbiote.commons.exceptions;

import org.springframework.http.HttpStatus;
import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.CustomAAMException;

/**
 * Custom exception thrown when an unauthorized client tries to register an application.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class UnauthorizedRegistrationException extends CustomAAMException{

    private static final long serialVersionUID = Constants.serialVersionUID;

    private final HttpStatus statusCode = HttpStatus.UNAUTHORIZED;
    private final static String errorMessage = "UNAUTHORIZED_APP_REGISTRATION";

    public UnauthorizedRegistrationException() {
        super(errorMessage);
    }

    public UnauthorizedRegistrationException(String message) {
        super(message);
    }

    public UnauthorizedRegistrationException(Throwable cause) {
        super(cause);
    }

    public UnauthorizedRegistrationException(String message, Throwable cause) {
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
