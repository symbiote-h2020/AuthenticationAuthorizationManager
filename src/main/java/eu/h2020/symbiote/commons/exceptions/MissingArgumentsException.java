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

	public MissingArgumentsException() {
		super(errorMessage);
	}

	public MissingArgumentsException(String message) {
		super(message);
	}

	public MissingArgumentsException(Throwable cause) {
		super(cause);
	}

	public MissingArgumentsException(String message, Throwable cause) {
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
