package eu.h2020.symbiote.commons.exceptions;

import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.CustomAAMException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when an unauthorized client tries to unregister an application.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class UnauthorizedUnregistrationException extends CustomAAMException{
    private static final long serialVersionUID = Constants.serialVersionUID;

    private final HttpStatus statusCode = HttpStatus.UNAUTHORIZED;
    private final static String errorMessage = "UNAUTHORIZED_APP_UNREGISTRATION";

    public UnauthorizedUnregistrationException() {
        super(errorMessage);
    }

    public UnauthorizedUnregistrationException(String message) {
        super(message);
    }

    public UnauthorizedUnregistrationException(Throwable cause) {
        super(cause);
    }

    public UnauthorizedUnregistrationException(String message, Throwable cause) {
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
