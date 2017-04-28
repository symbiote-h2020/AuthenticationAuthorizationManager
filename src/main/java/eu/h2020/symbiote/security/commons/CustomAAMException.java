package eu.h2020.symbiote.security.commons;

import eu.h2020.symbiote.security.commons.exceptions.MissingArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.WrongCredentialsException;
import org.springframework.http.HttpStatus;

/**
 * Abstract class implemented by custom exceptions in AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see MissingArgumentsException
 * @see WrongCredentialsException
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