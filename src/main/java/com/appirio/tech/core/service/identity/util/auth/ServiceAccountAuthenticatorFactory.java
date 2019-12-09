package com.appirio.tech.core.service.identity.util.auth;

import java.util.LinkedList;
import java.util.List;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ServiceAccountAuthenticatorFactory {

	@NotNull
	private String type;

	@Valid
	private List<ServiceAccount> accounts = new LinkedList<ServiceAccount>();

	@JsonProperty
	public String getType() {
		return type;
	}

	@JsonProperty
	public List<ServiceAccount> getAccounts() {
		return accounts;
	}
	
	public ServiceAccountAuthenticator createServiceAccountAuthenticator() {
		ServiceAccountAuthenticator authenticator = new ServiceAccountAuthenticator();
		authenticator.setAccounts(getAccounts());
		return authenticator;
	}
}
