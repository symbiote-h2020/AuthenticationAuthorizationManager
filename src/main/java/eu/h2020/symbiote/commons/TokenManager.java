package eu.h2020.symbiote.commons;

import org.springframework.stereotype.Component;

import eu.h2020.symbiote.commons.enums.Status;
import eu.h2020.symbiote.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.commons.json.RequestToken;

/**
 * Class for managing operations (creation, verification checking, etc.) on {@link eu.h2020.symbiote.commons.json.RequestToken} objects in token related
 * service ({@link eu.h2020.symbiote.services.TokenService}).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @see eu.h2020.symbiote.commons.json.RequestToken
 */
@Component
public class TokenManager {

    public RequestToken create(){

        return new RequestToken();
    }

    public RequestToken create(String token){

        return new RequestToken(token);
    }


    public CheckTokenRevocationResponse checkHomeTokenRevocation(RequestToken token) {

        // outcome (for now default is true)
    	CheckTokenRevocationResponse outcome = new CheckTokenRevocationResponse(Status.SUCCESS);

        // do checks...

        return outcome;
    }

}
