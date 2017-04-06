package eu.h2020.symbiote.commons.jwt;

import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import java.security.cert.X509Certificate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import eu.h2020.symbiote.commons.RegistrationManager;
import eu.h2020.symbiote.commons.exceptions.JWTCreationException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Set of functions for generating JWT tokens.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Component
public class JWTEngine {

	@Autowired
	private RegistrationManager regManager;
	
	private SecureRandom random = new SecureRandom();

	public String generateJWTToken(String aamID, String appId, Long tokenValidInterval, Map<String, Object> attributes, String appCert)
			throws JWTCreationException {

		String jti = String.valueOf(random.nextInt());

		try {
			//TODO use app public key once available from registration

			Map<String, Object> claimsMap = new HashMap<String,Object>();
			// Insert AAM Public Key
			claimsMap.put("ipk", regManager.getPlatformAAMPublicKey().getEncoded());

			//Insert application Public Key
			claimsMap.put("spk", regManager.getPlatformAAMPublicKey().getEncoded());
			
			//Add attributes to token
			if(attributes != null && !attributes.isEmpty()){
				for (Map.Entry<String, Object> entry : attributes.entrySet()){
					claimsMap.put(entry.getKey(), entry.getValue());
				}
			}
			
			JwtBuilder jwtBuilder = Jwts.builder();
			jwtBuilder.setId(jti);
			jwtBuilder.setIssuer(aamID);
			jwtBuilder.setSubject(appId);
			jwtBuilder.setIssuedAt(new Date());
			jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + tokenValidInterval));
			jwtBuilder.setClaims(claimsMap);
			jwtBuilder.signWith(SignatureAlgorithm.ES256, regManager.getPlatformAAMPrivateKey());

			return jwtBuilder.compact();
		} catch (Exception e) {
			e.printStackTrace();
			throw new JWTCreationException();
		}
	}
}
