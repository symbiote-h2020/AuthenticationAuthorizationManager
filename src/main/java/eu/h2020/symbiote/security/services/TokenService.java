package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.TokenManager;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.exceptions.aam.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.aam.TokenValidationException;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.repositories.TokenRepository;
import eu.h2020.symbiote.security.token.Token;
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

    public Token createFederatedHomeTokenForForeignToken(String foreignToken) throws JWTCreationException {
        Token retToken = tokenManager.createForeignToken(foreignToken);
        saveToken(retToken);
        return retToken;
    }

    /**
     * @param user which the token belongs to
     * @return Generates home token for given user
     * @throws JWTCreationException
     */
    public Token getHomeToken(User user) throws JWTCreationException {
        Token retToken = tokenManager.createHomeToken(user);
        saveToken(retToken);
        return retToken;
    }

    public CheckRevocationResponse checkHomeTokenRevocation(Token token) {
        return tokenManager.checkHomeTokenRevocation(token, tokenRepository.findByToken(token.getToken()));
    }

    public void removeAllTokens() {
        tokenRepository.deleteAll();
    }

    public void saveToken(Token token) {
        tokenRepository.save(token);
    }

    public Token getToken(String jwt) throws TokenValidationException {
        return new Token(tokenRepository.findByToken(jwt).getToken());
    }

    public List<Token> getAllTokens() {
        return tokenRepository.findAll();
    }
}
