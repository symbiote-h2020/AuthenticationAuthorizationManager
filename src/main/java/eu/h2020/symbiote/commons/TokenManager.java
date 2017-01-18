package eu.h2020.symbiote.commons;

import eu.h2020.symbiote.commons.enums.Status;
import eu.h2020.symbiote.commons.json.RequestToken;

import org.springframework.stereotype.Component;

@Component
public class TokenManager {

    public RequestToken create(){

        return new RequestToken();
    }

    public RequestToken create(String token){

        return new RequestToken(token);
    }

    //checkHomeTokenRevocation()
    public Status checkHomeTokenRevocation(RequestToken token) {

        // outcome (for now default is true)
        Status outcome = Status.SUCCESS;

        // do checks...

        return outcome;
    }

}
