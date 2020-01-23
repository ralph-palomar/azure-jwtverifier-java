package io.ralphp.jwtverifier;

import java.util.Base64;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JWTVerifier {

	private static final Logger log = LogManager.getRootLogger();
	
	public static Boolean verifyJWT(String token) {
		Boolean verified = false;
		DecodedJWT decodedJWT = JWT.decode(token);
		String decodedHeader = null;
		String decodedPayload = null;
		
		try {
			log.info("START:- Verifying JWT access token");
			decodedHeader = new String(Base64.getDecoder().decode(decodedJWT.getHeader().getBytes()), "UTF-8");
			decodedPayload = new String(Base64.getDecoder().decode(decodedJWT.getPayload().getBytes()), "UTF-8");			
			ObjectMapper mapper = new ObjectMapper();
			Map<String, Object> mapHeader = mapper.readValue(decodedHeader, new TypeReference<Map<String, Object>>(){});
			Map<String, Object> mapPayload = mapper.readValue(decodedPayload, new TypeReference<Map<String, Object>>(){});
			String keyId = (String) mapHeader.get("kid");
			String issuer = (String) mapPayload.get("iss");
			Algorithm algorithm = Algorithm.RSA256(new AzureRSAKeyProvider(keyId));
			com.auth0.jwt.JWTVerifier jwtVerifier = JWT.require(algorithm).withIssuer(issuer).build();
			jwtVerifier.verify(token);
			verified = true;
			log.info("SUCCESS:- Verifying JWT access token");
		} catch(Exception e) {
			log.error("EXCEPTION:- " + e.getMessage());
		}
		return verified;
	}
}
