package com.appirio.tech.core.service.identity.representation;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import com.appirio.tech.core.api.v3.model.AbstractIdResource;

public class Client extends AbstractIdResource {

	private String clientId;
	
	private String name;
	
	private String secret;

	private List<String> redirectUris = new LinkedList<>();

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public List<String> getRedirectUris() {
		return redirectUris;
	}

	public void setRedirectUris(List<String> redirectUris) {
		this.redirectUris = redirectUris;
	}

	public String getRedirectUri() {
		return redirectUris==null || redirectUris.size()==0 ? null : String.join("", redirectUris);
	}

	public void setRedirectUri(String redirectUri) {
		if(redirectUri==null || redirectUri.trim().length()==0)
			return;
		if(redirectUris==null)
			redirectUris = new LinkedList<>();
		else
			redirectUris.clear();
		Arrays.asList(redirectUri.split(",")).forEach(u -> redirectUris.add(u.trim()));
	}
}
