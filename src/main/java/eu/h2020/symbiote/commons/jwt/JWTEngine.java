package eu.h2020.symbiote.commons.jwt;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Map;

import org.springframework.stereotype.Component;

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

	private SecureRandom random = new SecureRandom();

	public String generateJWTToken(String aamID, String appId, Long tokenValidInterval, Map<String, Object> claimsMap)
			throws JWTCreationException {

		String jti = String.valueOf(random.nextInt());
		char[] KEY_STORE_PASSWD = { '1', '2', '3', '4', '5', '6', '7', };
		char[] PV_KEY_STORE_PASSWD = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };

		try {
			KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
			pkcs12Store.load(new FileInputStream("PlatformAAM.keystore"), KEY_STORE_PASSWD);
			PrivateKey pvKey = (PrivateKey) pkcs12Store.getKey("Platform AAM keystore", PV_KEY_STORE_PASSWD);
			PublicKey pubKey = pkcs12Store.getCertificate("Platform AAM keystore").getPublicKey();

			// Insert AAM Public Key
			claimsMap.put("ipk", pubKey.getEncoded());

			// TODO spk - get public key of the APP
			claimsMap.put("spk", pubKey.getEncoded());

			JwtBuilder jwtBuilder = Jwts.builder();
			jwtBuilder.setId(jti);
			jwtBuilder.setIssuer(aamID);
			jwtBuilder.setSubject(appId);
			jwtBuilder.setIssuedAt(new Date());
			jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + tokenValidInterval));
			jwtBuilder.setClaims(claimsMap);
			jwtBuilder.signWith(SignatureAlgorithm.ES256, pvKey);

			return jwtBuilder.compact();
		} catch (Exception e) {
			throw new JWTCreationException();
		}
	}
}
