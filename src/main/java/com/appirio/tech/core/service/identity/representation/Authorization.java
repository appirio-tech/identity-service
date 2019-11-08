package com.appirio.tech.core.service.identity.representation;

import com.appirio.tech.core.api.v3.model.AbstractIdResource;

public class Authorization extends AbstractIdResource {

	private String token;
	
	private String refreshToken;
	
	private String target;
	
	private String externalToken;
	
	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public String getTarget() {
		return target;
	}

	public void setTarget(String target) {
		this.target = target;
	}

	public String getExternalToken() {
		return externalToken;
	}

	public void setExternalToken(String externalToken) {
		this.externalToken = externalToken;
	}

	
	//Zendesk POC
	private String zendeskJwt;

	public String getZendeskJwt() {
		return zendeskJwt;
	}

	public void setZendeskJwt(String zendeskJwt) {
		this.zendeskJwt = zendeskJwt;
	}
}
