package eu.h2020.symbiote.security.commons.exceptions;

import eu.h2020.symbiote.security.commons.Constants;
import eu.h2020.symbiote.security.commons.CustomAAMException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when the AAM is misconfigured and attempted to run in this state
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class AAMMisconfigurationException extends CustomAAMException {

    private static final long serialVersionUID = Constants.serialVersionUID;
    private final static String errorMessage = "AAM_MISCONFIGURED";
    private final static HttpStatus statusCode = HttpStatus.INTERNAL_SERVER_ERROR;

    public AAMMisconfigurationException() {
        super(errorMessage);
    }

    public AAMMisconfigurationException(String message) {
        super(message);
    }

    public AAMMisconfigurationException(Throwable cause) {
        super(cause);
    }

    public AAMMisconfigurationException(String message, Throwable cause) {
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
