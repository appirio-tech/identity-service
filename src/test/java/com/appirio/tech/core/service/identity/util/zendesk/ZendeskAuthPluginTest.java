package com.appirio.tech.core.service.identity.util.zendesk;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;


import org.junit.Test;

import com.appirio.tech.core.api.v3.util.jwt.JWTToken;
import com.appirio.tech.core.service.identity.representation.Authorization;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

/**
 * ZendeskAuthPluginTest is used to test the ZendeskAuthPlugin
 * 
 * <p>
 * Changes in the verstion 1.1 (Topcoder - Provide Way to Refresh Auth0 Tokens In authorizations API v1.0)
 * - update the tests to use the classes from java jwt version 3.2.0
 * </p>
 * 
 * @author TCCoder
 * @version 1.1
 *
 */

public class ZendeskAuthPluginTest {

    /**
     * Test process
     *
     * @throws Exception if any error occurs
     */
	@Test
    public void testProcess() throws Exception {
		
		String userId = "JWT-USER-ID";
		String name   = "JWT-NAME";
		String email  = "JWT-EMAIL";

		String idPrefix = "ID-PREFIX";
		String secret = "SECRET";
		
		String token = createToken(userId, name, email, secret);
		
		Authorization auth = new Authorization();
		auth.setToken(token);
	
		// testee
		ZendeskAuthPlugin testee = spy(new ZendeskAuthPlugin());
		testee.setSecret(secret);
		testee.setIdPrefix(idPrefix);
		
		// test
		testee.process(auth);
		
		// check result
		assertEquals(token, auth.getToken());
		
		String zendeskJwt = auth.getZendeskJwt();
		assertNotNull(zendeskJwt);
		
		Verification verification = JWT.require(Algorithm.HMAC256(secret));
        JWTVerifier verifier = verification.build();
        DecodedJWT jwt = verifier.verify(zendeskJwt);

        
        assertEquals(idPrefix + ":" + userId, jwt.getClaim("external_id").asString());
        assertEquals(name, jwt.getClaim("name").asString());
        assertEquals(email, jwt.getClaim("email").asString());
        assertNotNull(jwt.getClaim("iat"));
        assertNotNull(jwt.getClaim("jti"));
		
	}
	
	@Test
	public void testProcess_ZendeskTokenIsNotCreatedWhenNameIsNullInSourceJWT() throws Exception {
		
		String userId = "JWT-USER-ID";
		String email  = "JWT-EMAIL";
		
		// test: name is null
		testProcess_CaseThatZendeskTokenIsNotCreated(userId, null, email);
	}
	
	@Test
	public void testProcess_ZendeskTokenIsNotCreatedWhenEmailIsNullInSourceJWT() throws Exception {
		
		String userId = "JWT-USER-ID";
		String name  = "JWT-NAME";
		
		// test: name is null
		testProcess_CaseThatZendeskTokenIsNotCreated(userId, name, null);
	}

	@Test
	public void testProcess_ZendeskTokenIsNotCreatedWhenUserIdIsNullInSourceJWT() throws Exception {
		
		String email  = "JWT-EMAIL";
		String name  = "JWT-NAME";
		
		// test: name is null
		testProcess_CaseThatZendeskTokenIsNotCreated(null, name, email);
	}

	
	protected void testProcess_CaseThatZendeskTokenIsNotCreated(String userId, String name, String email) throws Exception {
		
		String idPrefix = "ID-PREFIX";
		String secret = "SECRET";
		
		String token = createToken(userId, name, email, secret);
		
		Authorization auth = new Authorization();
		auth.setToken(token);
	
		// testee
		ZendeskAuthPlugin testee = spy(new ZendeskAuthPlugin());
		testee.setSecret(secret);
		testee.setIdPrefix(idPrefix);
		
		// test
		testee.process(auth);
		
		// check result
		assertEquals(token, auth.getToken());
		
		assertNull(auth.getZendeskJwt());
	}
	
	
	@Test
	public void testCreateExternalId() throws Exception {
		
		String userId = "JWT-USER-ID";
		String idPrefix = "ID-PREFIX";
		
		// testee
		ZendeskAuthPlugin testee = spy(new ZendeskAuthPlugin());
		testee.setIdPrefix(idPrefix);
		
		// test
		String result = testee.createExternalId(userId);
		
		// check result
		assertNotNull(result);
		assertEquals(idPrefix+":"+userId, result);
	}
	
	@Test
	public void testDecorateForTest_Prod() throws Exception {
		
		String name = "JWT-NAME";
		String idPrefix = "ID-PREFIX";
		
		// testee
		ZendeskAuthPlugin testee = spy(new ZendeskAuthPlugin());
		testee.setIdPrefix(idPrefix);
		
		// test
		String result = testee.decorateForTest(name);
		
		// check result
		assertNotNull(result);
		assertEquals(name, result);
	}
	
	@Test
	public void testDecorateForTest_Dev() throws Exception {
		
		String name = "JWT-NAME";
		String idPrefix = "ID-PREFIX-Dev";
		
		// testee
		ZendeskAuthPlugin testee = spy(new ZendeskAuthPlugin());
		testee.setIdPrefix(idPrefix);
		
		// test
		String result = testee.decorateForTest(name);
		
		// check result
		assertNotNull(result);
		assertEquals(name+"."+idPrefix, result);
	}
	
	@Test
	public void testDecorateForTest_QA() throws Exception {
		
		String name = "JWT-NAME";
		String idPrefix = "ID-PREFIX-QA";
		
		// testee
		ZendeskAuthPlugin testee = spy(new ZendeskAuthPlugin());
		testee.setIdPrefix(idPrefix);
		
		// test
		String result = testee.decorateForTest(name);
		
		// check result
		assertNotNull(result);
		assertEquals(name+"."+idPrefix, result);
	}

	protected String createToken(String userId, String name, String email, String secret) {
		JWTToken jwt = new JWTToken();
		jwt.setHandle(name);
		jwt.setEmail(email);
		jwt.setUserId(userId);
		String token = jwt.generateToken(secret);
		return token;
	}

}
