package com.appirio.tech.core.service.identity.util.zendesk;

import static org.junit.Assert.*;

import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

/**
 * ZendeskTokenGeneratorTest is used to 
 * 
 * <p>
 * Changes in the verstion 1.1 (Topcoder - Provide Way to Refresh Auth0 Tokens In authorizations API v1.0)
 * - update tests to use the classes from java jwt version 3.2.0
 * </p>
 * 
 * @author TCCoder
 * @version 1.1
 *
 */
public class ZendeskTokenGeneratorTest {

	@Test
	public void testGenerateToken() throws Exception {
		
		String userId = "JWT-USER-ID";
		String name   = "JWT-NAME";
		String email  = "JWT-EMAIL";
		String secret = "SECRET";

		// testee
		ZendeskTokenGenerator gen = new ZendeskTokenGenerator(secret);
		
		// test
		String result = gen.generateToken(userId, name, email);
		
		// check result
		assertNotNull(result);
		
		Verification verification = JWT.require(Algorithm.HMAC256(secret));
		JWTVerifier verifier = verification.build();
		DecodedJWT jwt = verifier.verify(result);

		
		assertEquals(userId, jwt.getClaim("external_id").asString());
		assertEquals(name, jwt.getClaim("name").asString());
		assertEquals(email, jwt.getClaim("email").asString());
		assertNotNull(jwt.getClaim("iat"));
		assertNotNull(jwt.getClaim("jti"));
	}

}
