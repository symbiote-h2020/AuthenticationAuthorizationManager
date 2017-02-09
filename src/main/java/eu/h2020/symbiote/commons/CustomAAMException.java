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

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param   message   the detail message.
     */
    public CustomAAMException(String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified cause.
     *
     * @param   cause   the exception cause.
     */
    public CustomAAMException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param   message   the detail message.
     * @param   cause   the exception cause.
     */
    public CustomAAMException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Abstract method to be overridden in order to return the HTTP status code of this exception.
     *
     * @return {@link org.springframework.http.HttpStatus} of this {@code CustomAAMException} instance.
     */
    public abstract HttpStatus getStatusCode();

    /**
     * Abstract method to be overridden in order to return the error message of this exception.
     *
     * @return error message of this {@code CustomAAMException} instance.
     */
    public abstract String getErrorMessage();

}