package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.TokenManager;
import eu.h2020.symbiote.security.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.security.commons.json.CheckTokenRevocationResponse;
import eu.h2020.symbiote.security.commons.json.RequestToken;
import eu.h2020.symbiote.security.repositories.TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Spring service used to provide token related functionality of the AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Service
public class TokenService {

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
        tokenRepository.save(new Token(token));
    }

    public Token getToken(String jwt) {
        return tokenRepository.findByToken(jwt);
    }

    public List<Token> getAllTokens() {
        return tokenRepository.findAll();
    }
}
