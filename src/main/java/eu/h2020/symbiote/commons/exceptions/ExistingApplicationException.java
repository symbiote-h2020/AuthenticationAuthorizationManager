package eu.h2020.symbiote.commons.exceptions;

import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.CustomAAMException;
import org.springframework.http.HttpStatus;


/**
 * Custom exception thrown when application credentials are already present in DB during registration procedure in {@link eu.h2020.symbiote.services.ApplicationRegistrationService}.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class ExistingApplicationException extends CustomAAMException {
    private static final long serialVersionUID = Constants.serialVersionUID;

    private final HttpStatus statusCode = HttpStatus.BAD_REQUEST;
    private final static String errorMessage = "APP_ALREADY_REGISTERED";

    public ExistingApplicationException() {
        super(errorMessage);
    }

    public ExistingApplicationException(String message) {
        super(message);
    }

    public ExistingApplicationException(Throwable cause) {
        super(cause);
    }

    public ExistingApplicationException(String message, Throwable cause) {
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
