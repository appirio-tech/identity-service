package com.appirio.tech.core.service.identity.util.zendesk;

import javax.validation.constraints.NotNull;

public class ZendeskFactory {

	@NotNull
	private String secret;
	
	@NotNull
	private String idPrefix;
	
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

	public ZendeskAuthPlugin createAuthPlugin() {
		ZendeskAuthPlugin plugin = new ZendeskAuthPlugin();
		plugin.setSecret(this.secret);
		plugin.setIdPrefix(this.idPrefix);
		return plugin;
	}
}
