package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.TokenManager;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.security.commons.payloads.CheckTokenRevocationResponse;
import eu.h2020.symbiote.security.commons.payloads.RequestToken;
import eu.h2020.symbiote.security.repositories.TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

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

    /**
     *
     * @param user which the token belongs to
     * @return Generates home token for given user
     * @throws JWTCreationException
     */
    public RequestToken getHomeToken(User user) throws JWTCreationException {
        RequestToken retToken = tokenManager.createHomeToken(user);
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
