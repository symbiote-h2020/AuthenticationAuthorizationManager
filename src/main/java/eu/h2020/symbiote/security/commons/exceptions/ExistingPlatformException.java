package eu.h2020.symbiote.security.commons.exceptions;

import eu.h2020.symbiote.security.commons.Constants;
import eu.h2020.symbiote.security.commons.CustomAAMException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when platform is already present in DB during registration procedure in
 * {@link eu.h2020.symbiote.security.services.PlatformRegistrationService}.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class ExistingPlatformException extends CustomAAMException {

    private static final long serialVersionUID = Constants.serialVersionUID;
    public final static String errorMessage = "PLATFORM_ALREADY_REGISTERED";
    private final static HttpStatus statusCode = HttpStatus.BAD_REQUEST;

    public ExistingPlatformException() {
        super(errorMessage);
    }

    public ExistingPlatformException(String message) {
        super(message);
    }

    public ExistingPlatformException(Throwable cause) {
        super(cause);
    }

    public ExistingPlatformException(String message, Throwable cause) {
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
