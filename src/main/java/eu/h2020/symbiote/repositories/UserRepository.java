package eu.h2020.symbiote.repositories;

import eu.h2020.symbiote.model.UserModel;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface UserRepository extends MongoRepository<UserModel, String>{}
