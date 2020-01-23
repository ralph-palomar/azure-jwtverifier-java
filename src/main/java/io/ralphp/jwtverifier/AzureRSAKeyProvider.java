package io.ralphp.jwtverifier;

import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.interfaces.RSAKeyProvider;

public class AzureRSAKeyProvider implements RSAKeyProvider {

	private static final Logger log = LogManager.getRootLogger();
	private String keyId;
	
	public AzureRSAKeyProvider(String keyId) {
		this.keyId = keyId;
	}

	public RSAPrivateKey getPrivateKey() {
		return null;
	}

	public String getPrivateKeyId() {
		return null;
	}

	public RSAPublicKey getPublicKeyById(String arg0) {
		log.info("START:- Get Public Key by ID >>> " + arg0);
		URL url = null;
		JwkProvider jwkProvider = null;
		Jwk jwk = null;
		RSAPublicKey rsaPublicKey = null;
		try {
			url = new URL("https://login.microsoftonline.com/common/discovery/keys");
			jwkProvider = new JwkProviderBuilder(url).build();
			jwk = jwkProvider.get(keyId);
			rsaPublicKey = (RSAPublicKey) jwk.getPublicKey();
		} catch(Exception e) {
			log.error("EXCEPTION:- " + e.getMessage());
		}
		log.info("SUCCESS:- Get Public Key by ID");
		return rsaPublicKey;
	}

}
