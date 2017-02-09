package eu.h2020.symbiote.commons.exceptions;

import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.CustomAAMException;
import org.springframework.http.HttpStatus;


/**
 * Custom exception thrown when username and/or password credentials are missing during login procedure in {@link eu.h2020.symbiote.services.LoginService}.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class MissingArgumentsException extends CustomAAMException {

	private static final long serialVersionUID = Constants.serialVersionUID;

	private final HttpStatus statusCode = HttpStatus.BAD_REQUEST;
	private final static String errorMessage = "ERR_MISSING_ARGUMENTS";

	/**
	 * Constructs a new exception with default {@link #errorMessage}.
	 */
	public MissingArgumentsException() {
		super(errorMessage);
	}

	/**
	 * Constructs a new exception with the specified detail message.
	 *
	 * @param message the detail message.
	 */
	public MissingArgumentsException(String message) {
		super(message);
	}

	/**
	 * Constructs a new exception with the specified cause.
	 *
	 * @param   cause   the exception cause.
	 */
	public MissingArgumentsException(Throwable cause) {
		super(cause);
	}

	/**
	 * Constructs a new exception with the specified detail message and cause.
	 *
	 * @param   message   the detail message.
	 * @param   cause   the exception cause.
	 */
	public MissingArgumentsException(String message, Throwable cause) {
		super(message, cause);
	}

    /**
     * Returns the HTTP status code of this exception.
     *
     * @return {@link org.springframework.http.HttpStatus} of this {@code MissingArgumentsException} instance.
     */
	@Override
	public HttpStatus getStatusCode() {
		return statusCode;
	}

    /**
     * Returns the error message of this exception.
     *
     * @return error message of this {@code MissingArgumentsException} instance.
     */
	@Override
	public String getErrorMessage() {
		return errorMessage;
	}

}
