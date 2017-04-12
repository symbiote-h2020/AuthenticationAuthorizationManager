package eu.h2020.symbiote.commons.jwt;

import eu.h2020.symbiote.commons.Constants;
import eu.h2020.symbiote.commons.RegistrationManager;
import eu.h2020.symbiote.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.commons.exceptions.MalformedJWTException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Set of functions for generating JWT tokens.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Component
public class JWTEngine {

    private static org.apache.commons.logging.Log log = LogFactory.getLog(JWTEngine.class);

    private final RegistrationManager regManager;

    private SecureRandom random = new SecureRandom();

    @Value("${symbiote.aam.token.validityMillis}")
    private Long tokenValidity;

    @Value("${platform.id}")
    private String platformId;

    @Autowired
    public JWTEngine(RegistrationManager regManager) {
        this.regManager = regManager;
    }

    public String generateJWTToken(String appId, Map<String, Object> attributes, byte[] appCert)
        throws JWTCreationException {

        String jti = String.valueOf(random.nextInt());

        try {
            //TODO use app public key once available from registration

            Map<String, Object> claimsMap = new HashMap<String, Object>();
            // Insert AAM Public Key
            claimsMap.put("ipk", regManager.getPlatformAAMPublicKey().getEncoded());

            //Insert issuee Public Key
            claimsMap.put("spk", appCert);

            //Add attributes to token
            if (attributes != null && !attributes.isEmpty()) {
                for (Map.Entry<String, Object> entry : attributes.entrySet()) {
                    claimsMap.put(entry.getKey(), entry.getValue());
                }
            }

            JwtBuilder jwtBuilder = Jwts.builder();
            jwtBuilder.setClaims(claimsMap);
            jwtBuilder.setId(jti);
            jwtBuilder.setIssuer(platformId);
            jwtBuilder.setSubject(appId);
            jwtBuilder.setIssuedAt(new Date());
            jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + tokenValidity));
            jwtBuilder.signWith(SignatureAlgorithm.ES256, regManager.getPlatformAAMPrivateKey());

            return jwtBuilder.compact();
        } catch (Exception e) {
            e.printStackTrace();
            throw new JWTCreationException();
        }
    }

    public JWTClaims getClaimsFromToken(String jwtToken) throws MalformedJWTException, JSONException {

        HashMap<String, Object> retMap = new HashMap<String, Object>();
        String[] jwtParts = jwtToken.split("\\.");
        if (jwtParts.length < Constants.JWTPartsCount) {
            throw new MalformedJWTException();
        }
        //Get second part of the JWT
        String jwtBody = jwtParts[1];

        String claimsString = StringUtils.newStringUtf8(Base64.decodeBase64(jwtBody));

        JSONObject jwtFields = new JSONObject(claimsString);

        Iterator<String> jwtKeys = jwtFields.keys();
        while (jwtKeys.hasNext()) {
            String key = jwtKeys.next();
            Object value = jwtFields.get(key);
            retMap.put(key, value);
        }
        return new JWTClaims(retMap.get("jti"), retMap.get("alg"), retMap.get("iss"), retMap.get("sub"), retMap
            .get("iat"), retMap.get("exp"), retMap.get("ipk"), retMap.get("spk"), retMap.get("att"));
    }

}

