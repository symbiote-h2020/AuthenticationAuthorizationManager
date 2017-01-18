package eu.h2020.symbiote.repositories;

import eu.h2020.symbiote.model.TokenModel;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface TokenRepository extends MongoRepository<TokenModel, String>{}
