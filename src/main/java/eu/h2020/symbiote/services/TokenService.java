package eu.h2020.symbiote.services;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import eu.h2020.symbiote.commons.TokenManager;
import eu.h2020.symbiote.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.model.TokenModel;
import eu.h2020.symbiote.repositories.TokenRepository;

/**
 * Spring service used to provide token related functionalities of CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Service
public class TokenService {

	// FIXME harcoded values for now
	private final String aamID = "dummyAAM";
	private final String appID = "dummyAPP";
	private final Long tokenValidTime = new Long(1000 * 60 * 60 * 24); // one
																		// day
																		// token
																		// validity
																		// time

	private final Map<String, Object> attributes = new HashMap<String, Object>(); // empty
																					// claims
																					// map
	@Autowired
	private TokenRepository tokenRepository;
	@Autowired
	private TokenManager tokenManager;

	public TokenModel create() throws JWTCreationException {
		return new TokenModel(tokenManager.create(aamID, appID, tokenValidTime, attributes));
	}

	public RequestToken getDefaultForeignToken() throws JWTCreationException {
		return tokenManager.create(aamID, appID, tokenValidTime, attributes);
	}

	public RequestToken getDefaultHomeToken() throws JWTCreationException {
		return tokenManager.create(aamID, appID, tokenValidTime, attributes);
	}

	public CheckTokenRevocationResponse checkHomeTokenRevocation(RequestToken token) {
		return tokenManager.checkHomeTokenRevocation(token);
	}

	public void removeAllTokens() {
		tokenRepository.deleteAll();
	}

	public void saveToken(RequestToken token) {
		tokenRepository.save(new TokenModel(token.getToken()));
	}

	public List<TokenModel> getAllTokens() {
		return tokenRepository.findAll();
	}
}