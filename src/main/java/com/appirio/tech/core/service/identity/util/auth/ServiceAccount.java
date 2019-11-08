package com.appirio.tech.core.service.identity.util.auth;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ServiceAccount {

	@NotNull
	private String clientId;
	
	@NotNull
	private String clientSecret;
	
	@NotNull
	private String contextUserId;

	@JsonProperty
	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	@JsonProperty
	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	@JsonProperty
	public String getContextUserId() {
		return contextUserId;
	}

	public void setContextUserId(String contextUserId) {
		this.contextUserId = contextUserId;
	}
}
