package eu.h2020.symbiote.commons.jwt;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Map;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;

/**
 * Set of functions for generating JWT tokens.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Component
public class JWTEngine {

	private SecureRandom random = new SecureRandom();

	public String generateJWTToken(String aamID, String appId, Long tokenValidInterval, Map<String, Object> claimsMap) {

		String jti = String.valueOf(random.nextInt());

		Key key = MacProvider.generateKey();

		JwtBuilder jwtBuilder = Jwts.builder();
		jwtBuilder.setId(jti);
		jwtBuilder.setIssuer(aamID);
		jwtBuilder.setSubject(appId);
		jwtBuilder.setIssuedAt(new Date());
		jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + tokenValidInterval));
		jwtBuilder.setClaims(claimsMap);
		//TODO change to ES256 once you get private key
		jwtBuilder.signWith(SignatureAlgorithm.HS256, key);

		//TODO ipk,spk
		
		return jwtBuilder.compact();
	}
}
