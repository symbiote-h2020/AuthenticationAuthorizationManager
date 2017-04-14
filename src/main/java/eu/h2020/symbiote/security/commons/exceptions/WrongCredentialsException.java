package eu.h2020.symbiote.security.commons.exceptions;

import eu.h2020.symbiote.security.commons.Constants;
import eu.h2020.symbiote.security.commons.CustomAAMException;
import eu.h2020.symbiote.security.services.LoginService;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when a app/user provides wrong credentials during login procedure in
 * {@link LoginService}
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class WrongCredentialsException extends CustomAAMException {

    private static final long serialVersionUID = Constants.serialVersionUID;
    private final static String errorMessage = "ERR_WRONG_CREDENTIALS";
    private final HttpStatus statusCode = HttpStatus.UNAUTHORIZED;

    public WrongCredentialsException() {
        super(errorMessage);
    }

    public WrongCredentialsException(String message) {
        super(message);
    }

    public WrongCredentialsException(Throwable cause) {
        super(cause);
    }

    public WrongCredentialsException(String message, Throwable cause) {
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
