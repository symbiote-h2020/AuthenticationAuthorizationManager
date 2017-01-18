package eu.h2020.symbiote.commons;

/**
 * Created by Nemanja on 14.12.2016.
 */

import org.springframework.http.HttpStatus;

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