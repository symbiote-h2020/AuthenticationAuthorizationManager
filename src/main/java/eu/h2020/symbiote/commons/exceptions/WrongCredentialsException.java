package eu.h2020.symbiote.commons.exceptions;

import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.CustomAAMException;
import org.springframework.http.HttpStatus;

/**
 * Custom exception thrown when a app/user provides wrong credentials during login procedure in {@link eu.h2020.symbiote.services.LoginService}
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class WrongCredentialsException extends CustomAAMException {

	private static final long serialVersionUID = Constants.serialVersionUID;

	private final HttpStatus statusCode = HttpStatus.UNAUTHORIZED;
	private final static String errorMessage = "ERR_WRONG_CREDENTIALS";

    /**
     * Constructs a new exception with default {@link #errorMessage}.
     */
	public WrongCredentialsException() {
		super(errorMessage);
	}

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param message the detail message.
     */
	public WrongCredentialsException(String message) {
		super(message);
	}

    /**
     * Constructs a new exception with the specified cause.
     *
     * @param   cause   the exception cause.
     */
	public WrongCredentialsException(Throwable cause) {
		super(cause);
	}

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param   message   the detail message.
     * @param   cause   the exception cause.
     */
	public WrongCredentialsException(String message, Throwable cause) {
		super(message, cause);
	}

    /**
     * Returns the HTTP status code of this exception.
     *
     * @return {@link org.springframework.http.HttpStatus} of this {@code WrongCredentialsException} instance.
     */
	@Override
	public HttpStatus getStatusCode() {
		return statusCode;
	}

    /**
     * Returns the error message of this exception.
     *
     * @return error message of this {@code WrongCredentialsException} instance.
     */
	@Override
	public String getErrorMessage() {
		return errorMessage;
	}

}
