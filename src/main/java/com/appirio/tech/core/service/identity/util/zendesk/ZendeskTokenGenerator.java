package com.appirio.tech.core.service.identity.util.zendesk;

import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.UUID;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;

/**
 * ZendeskTokenGenerator is used to generate the token for the zendesk auth plugin. 
 * 
 * <p>
 * Chaneges in the verstion 1.1 (Topcoder - Provide Way to Refresh Auth0 Tokens In authorizations API v1.0)
 * - generateToken is changed to use the classes from the java jwt version 3.2.0
 * </p>
 * 
 * @author TCCoder
 * @version 1.1
 *
 */

public class ZendeskTokenGenerator {

	private String secret;

	public ZendeskTokenGenerator() {
	}

	public ZendeskTokenGenerator(String secret) {
		this.secret = secret;
	}

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}
	
	/**
     * Generate token
     *
     * @param userId the userId to use
     * @param name the name to use
     * @param email the email to use
     * @return the signed token result
     */
    public String generateToken(String userId, String name, String email) {
		
		Builder builder = JWT.create();
		builder.withClaim("email", email).withClaim("name", name).withClaim("external_id", userId)
		    .withIssuedAt(new Date()).withJWTId(UUID.randomUUID().toString());
		try {
		    return builder.sign(com.auth0.jwt.algorithms.Algorithm.HMAC256(secret));
		} catch (UnsupportedEncodingException exp) {
		    // should never catch the exp here
		    exp.printStackTrace();
		    return null;
		}
	}
}
