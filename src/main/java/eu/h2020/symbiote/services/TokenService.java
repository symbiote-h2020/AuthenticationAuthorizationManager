package eu.h2020.symbiote.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import eu.h2020.symbiote.commons.TokenManager;
import eu.h2020.symbiote.commons.enums.Status;
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

    @Autowired
    private TokenRepository tokenRepository;
    @Autowired
    private TokenManager tokenManager;

    public TokenModel create(String requestTokenStr) {
        return new TokenModel(tokenManager.create(requestTokenStr));
    }

    public RequestToken getDefaultForeignToken() {
        return tokenManager.create("foreign_token_from_platform_aam");
    }

    public RequestToken getDefaultHomeToken() {
        return tokenManager.create("home_token_from_platform_aam");
    }

    public Status checkHomeTokenRevocation(RequestToken token) {
        return tokenManager.checkHomeTokenRevocation(token);
    }

    public void removeAllTokens() { tokenRepository.deleteAll(); }

    public void saveToken(RequestToken token) { tokenRepository.save(new TokenModel(token.getToken())); }

    public List<TokenModel> getAllTokens() { return tokenRepository.findAll(); }
}