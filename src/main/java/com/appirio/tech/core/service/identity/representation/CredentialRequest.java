package com.appirio.tech.core.service.identity.representation;

public class CredentialRequest {

	private String email;
	private String connectionId;

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getConnectionId() {
		return connectionId;
	}

	public void setConnectionId(String connectionId) {
		this.connectionId = connectionId;
	}
}
