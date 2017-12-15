package eu.h2020.symbiote.security.repositories.entities;

import org.springframework.data.annotation.Id;

/**
 * Class prepared for MongoDB to store token identifiers (token issuer + @ + token id ).
 *
 * @author Jakub Toczek (PSNC)
 */
public class RevokedRemoteToken {
    @Id
    private final String id;

    public RevokedRemoteToken(String id) {
        this.id = id;
    }
}
