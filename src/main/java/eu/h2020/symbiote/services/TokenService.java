package eu.h2020.symbiote.services;

import eu.h2020.symbiote.commons.TokenManager;
import eu.h2020.symbiote.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.commons.json.RequestToken;
import eu.h2020.symbiote.model.TokenModel;
import eu.h2020.symbiote.repositories.TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Spring service used to provide token related functionalities of CloudAAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Service
public class TokenService {

    // FIXME harcoded values for now
    private final String appID = "dummyAPP";

    private final Map<String, Object> attributes = new HashMap<String, Object>(); // empty
    // claims
    // map
    private final TokenRepository tokenRepository;
    private final TokenManager tokenManager;

    @Autowired
    public TokenService(TokenRepository tokenRepository, TokenManager tokenManager) {
        this.tokenRepository = tokenRepository;
        this.tokenManager = tokenManager;
    }

    public RequestToken exchangeForForeignToken(String foreignToken) throws JWTCreationException {
        RequestToken retToken = tokenManager.createForeignToken(foreignToken);
        saveToken(retToken);
        return retToken;
    }

    public RequestToken getHomeToken() throws JWTCreationException {
        RequestToken retToken = tokenManager.createHomeToken();
        saveToken(retToken);
        return retToken;
    }

    public CheckTokenRevocationResponse checkHomeTokenRevocation(RequestToken token) {
        return tokenManager.checkHomeTokenRevocation(token, getToken(token.getToken()));
    }

    public void removeAllTokens() {
        tokenRepository.deleteAll();
    }

    public void saveToken(RequestToken token) {
        tokenRepository.save(new TokenModel(token));
    }

    public TokenModel getToken(String jwt) {
        return tokenRepository.findByToken(jwt);
    }

    public List<TokenModel> getAllTokens() {
        return tokenRepository.findAll();
    }
}
