package eu.h2020.symbiote.security.commons.jwt;

import eu.h2020.symbiote.security.commons.Constants;
import eu.h2020.symbiote.security.commons.RegistrationManager;
import eu.h2020.symbiote.security.commons.User;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.MalformedJWTException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Set of functions for generating JWT tokens.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
@Component
public class JWTEngine {

    public static final String SYMBIOTE_ATTRIBUTES_PREFIX = "SYMBIOTE_";
    private static Log log = LogFactory.getLog(JWTEngine.class);

    private final RegistrationManager regManager;

    private SecureRandom random = new SecureRandom();

    @Value("${aam.deployment.token.validityMillis}")
    private Long tokenValidity;

    @Value("${aam.deployment.id}")
    private String deploymentID = "";

    @Value("${aam.deployment.type}")
    private IssuingAuthorityType deploymentType = IssuingAuthorityType.NULL;

    @Autowired
    public JWTEngine(RegistrationManager regManager) {
        this.regManager = regManager;
    }

    public static JWTClaims getClaimsFromToken(String jwtToken) throws MalformedJWTException, JSONException {

        HashMap<String, Object> retMap = new HashMap<String, Object>();
        String[] jwtParts = jwtToken.split("\\.");
        if (jwtParts.length < Constants.JWTPartsCount) {
            throw new MalformedJWTException();
        }
        //Get second part of the JWT
        String jwtBody = jwtParts[1];

        String claimsString = StringUtils.newStringUtf8(Base64.decodeBase64(jwtBody));

        JSONObject jwtFields = new JSONObject(claimsString);

        Map<String, String> attributes = new HashMap<>();
        Iterator<String> jwtKeys = jwtFields.keys();
        while (jwtKeys.hasNext()) {
            String key = jwtKeys.next();
            Object value = jwtFields.get(key);
            if (key.startsWith(SYMBIOTE_ATTRIBUTES_PREFIX))
                attributes.put(key.substring(SYMBIOTE_ATTRIBUTES_PREFIX.length()), (String) value);
            else
                retMap.put(key, value);
        }
        return new JWTClaims(retMap.get("jti"), retMap.get("alg"), retMap.get("iss"), retMap.get("sub"), retMap
                .get("iat"), retMap.get("exp"), retMap.get("ipk"), retMap.get("spk"), retMap.get("ttyp"), attributes);
    }

    public String generateJWTToken(User user, Map<String, String> attributes) throws JWTCreationException, IOException, CertificateException {
        return this.generateJWTToken(user.getUsername(), attributes, regManager.convertPEMToX509(user.getCertificate().getPemCertificate()).getPublicKey().getEncoded());
    }

    public String generateJWTToken(String userId, Map<String, String> attributes,byte[] userPublicKey) throws JWTCreationException {

        String jti = String.valueOf(random.nextInt());
        Map<String, Object> claimsMap = new HashMap<String, Object>();

        try {
            // Insert AAM Public Key

            claimsMap.put("ipk", Base64.encodeBase64String(regManager.getAAMPublicKey().getEncoded()));

            //Insert issuee Public Key
            claimsMap.put("spk", Base64.encodeBase64String(userPublicKey));


            //Add symbIoTe related attributes to token
            if (attributes != null && !attributes.isEmpty()) {
                for (Map.Entry<String, String> entry : attributes.entrySet()) {
                    claimsMap.put(SYMBIOTE_ATTRIBUTES_PREFIX + entry.getKey(), entry.getValue());
                }
            }

            //Insert token type based on AAM deployment type (Core or Platform)
            switch (deploymentType) {
                case CORE:
                    claimsMap.put("ttyp", IssuingAuthorityType.CORE);
                    break;
                case PLATFORM:
                    claimsMap.put("ttyp", IssuingAuthorityType.PLATFORM);
                    break;
                case NULL:
                    throw new JWTCreationException("uninitialized deployment type, must be CORE or PLATFORM");
            }

            JwtBuilder jwtBuilder = Jwts.builder();
            jwtBuilder.setClaims(claimsMap);
            jwtBuilder.setId(jti);
            jwtBuilder.setIssuer(deploymentID);
            jwtBuilder.setSubject(userId);
            jwtBuilder.setIssuedAt(new Date());
            jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + tokenValidity));
            jwtBuilder.signWith(SignatureAlgorithm.ES256, regManager.getAAMPrivateKey());

            return jwtBuilder.compact();
        } catch (Exception e) {
            String message = "JWT creation error";
            log.error(message, e);
            throw new JWTCreationException(message, e);
        }
    }
}

