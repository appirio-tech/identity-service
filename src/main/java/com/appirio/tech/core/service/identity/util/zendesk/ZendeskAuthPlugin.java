package com.appirio.tech.core.service.identity.util.zendesk;

import com.appirio.tech.core.api.v3.util.jwt.JWTToken;
import com.appirio.tech.core.service.identity.representation.Authorization;

public class ZendeskAuthPlugin {

	private String secret;
	
	private String idPrefix;
	
	public Authorization process(Authorization auth) {
		if(auth==null)
			return auth;
		ZendeskTokenGenerator tokenGenerator = new ZendeskTokenGenerator(this.secret);
		JWTToken jwt = parse(auth.getToken());
		
		if(jwt.getUserId()==null || jwt.getHandle()==null || jwt.getEmail()==null)
			return auth;
		
		String zendeskJwt = tokenGenerator.generateToken(createExternalId(jwt.getUserId()), decorateForTest(jwt.getHandle()), decorateForTest(jwt.getEmail()));
		auth.setZendeskJwt(zendeskJwt);
		return auth;
	}
	
	protected JWTToken parse(String token) {
		JWTToken jwt = new JWTToken();
		jwt.apply(token);
		return jwt;
	}
	
	protected String createExternalId(String id) {
		return this.idPrefix + ":" + id;
	}

	protected String decorateForTest(String value) {
		return (isProduction(this.idPrefix)) ?
				value :
				value + "." + this.idPrefix;
	}
	
	protected boolean isProduction(String idPrefix) {
		if(idPrefix==null)
			return true;
		
		String lower = idPrefix.toLowerCase();
		return !lower.contains("dev") && ! lower.contains("qa"); 
	}

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public String getIdPrefix() {
		return idPrefix;
	}

	public void setIdPrefix(String idPrefix) {
		this.idPrefix = idPrefix;
	}
}
