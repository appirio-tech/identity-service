package com.appirio.tech.core.service.identity.util.auth;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.util.jwt.InvalidTokenException;
import com.appirio.tech.core.api.v3.util.jwt.JWTToken;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.util.Utils;


/**
 * Represents the OneTimeToken
 * 
 * <p>
 * Changes in the version 1.1 (Fast 48hrs!! Topcoder Identity Service - Support Event Bus Publishing v1.0)
 * - create the token with valid issuers
 * </p>
 * 
 * @author TCCoder
 * @version 1.1
 *
 */
public class OneTimeToken extends JWTToken {
	
	public OneTimeToken(String token, String domain, String secret) {
		super(token, secret, Utils.getValidIssuers());
		if(!isValidIssuerFor(domain))
			throw new InvalidTokenException(token, "Valid credentials are required.", null);
	}
	
	public AuthUser getAuthUser() {
    	final TCID uid = new TCID(getUserId());
        return new AuthUser() {
        	@Override public TCID getUserId() { return uid; }
        };
    }
}