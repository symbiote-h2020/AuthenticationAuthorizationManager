package eu.h2020.symbiote.commons;

import org.springframework.http.HttpStatus;

/**
 * Abstract class implemented by custom exceptions in Cloud AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see eu.h2020.symbiote.commons.exceptions.MissingArgumentsException
 * @see eu.h2020.symbiote.commons.exceptions.WrongCredentialsException
 */
public abstract class CustomAAMException extends Exception {

	public static final long serialVersionUID = Constants.serialVersionUID;
	
    public CustomAAMException(String message) {
        super(message);
    }

    public CustomAAMException(Throwable cause) {
        super(cause);
    }

    public CustomAAMException(String message, Throwable cause) {
        super(message, cause);
    }

    public abstract HttpStatus getStatusCode();

    public abstract String getErrorMessage();

}