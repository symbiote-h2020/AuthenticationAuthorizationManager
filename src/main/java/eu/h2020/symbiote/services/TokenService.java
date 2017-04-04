package eu.h2020.symbiote.services;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.tomcat.util.http.fileupload.IOUtils;
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
	private final String appCert =
            "\t-----BEGIN CERTIFICATE-----\n" +
			"\tMIIBQTCB6KADAgECAgEBMAoGCCqGSM49BAMCMCkxFDASBgNVBCkMC1BsYXRmb3Jt\n" +
			"\tQUFNMREwDwYDVQQKDAhTWU1CSU9URTAeFw0xNzAzMzExMjE3NTRaFw0xODAzMzEx\n" +
			"\tMjE3NTRaMCwxFzAVBgNVBCkMDk5ld0FwcGxpY2F0aW9uMREwDwYDVQQKDAhTWU1C\n" +
			"\tSU9URTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMABe/x3KDK8voWfdLQJJ4Cx\n" +
			"\t2BsplQIGFEPbMKtayRDsM6dR9pqO9lET4DWFMPsMOFdU9zoXvc+DsKNZGqxqCXIw\n" +
			"\tCgYIKoZIzj0EAwIDSAAwRQIhAMoglWZAOiP8oId+yYj1hrZ91VDqGrxfBZ8v39tC\n" +
			"\tJQlXAiBzygBYAVrbHjgmcQ7RFJmox/Q+XZNIVxV42YgxnpVgbA==\n" +
			"\t-----END CERTIFICATE-----";

	private final Long tokenValidTime = new Long(1000 * 60 * 60 * 24); // one
																		// day
																		// token
																		// validity
																		// time

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

	public TokenModel create() throws JWTCreationException {
		return new TokenModel(tokenManager.create(aamID, appID, tokenValidTime, attributes,appCert));
	}

	public RequestToken getDefaultForeignToken() throws JWTCreationException {
		return tokenManager.create(aamID, appID, tokenValidTime, attributes,appCert);
	}

	public RequestToken getDefaultHomeToken() throws JWTCreationException {
		return tokenManager.create(aamID, appID, tokenValidTime, attributes,appCert);
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