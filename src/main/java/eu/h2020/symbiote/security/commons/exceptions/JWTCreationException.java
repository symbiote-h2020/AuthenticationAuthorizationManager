package eu.h2020.symbiote.security.commons.exceptions;

import eu.h2020.symbiote.security.commons.Constants;
import eu.h2020.symbiote.security.commons.CustomAAMException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when JWT token creation fails
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class JWTCreationException extends CustomAAMException {

    private static final long serialVersionUID = Constants.serialVersionUID;
    private final static String errorMessage = "UNABLE_CREATE_JWT_TOKEN";
    private final HttpStatus statusCode = HttpStatus.BAD_REQUEST;

    public JWTCreationException() {
        super(errorMessage);
    }

    public JWTCreationException(String message) {
        super(message);
    }

    public JWTCreationException(Throwable cause) {
        super(cause);
    }

    public JWTCreationException(String message, Throwable cause) {
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