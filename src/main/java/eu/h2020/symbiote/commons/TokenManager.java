package eu.h2020.symbiote.commons;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import eu.h2020.symbiote.commons.enums.Status;
import eu.h2020.symbiote.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.commons.jwt.JWTEngine;

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
	
	@Autowired
	private JWTEngine jwtEngine;

    public RequestToken create(String aamID, String appId, Long tokenValidInterval, Map<String, Object> claimsMap){

        return new RequestToken(jwtEngine.generateJWTToken(aamID,appId,tokenValidInterval,claimsMap));
    }


    public CheckTokenRevocationResponse checkHomeTokenRevocation(RequestToken token) {

        // outcome (for now default is true)
    	CheckTokenRevocationResponse outcome = new CheckTokenRevocationResponse(Status.SUCCESS);

        // do checks...

        return outcome;
    }

}
