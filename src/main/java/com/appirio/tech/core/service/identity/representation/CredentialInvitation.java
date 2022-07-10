package com.appirio.tech.core.service.identity.representation;

public class CredentialInvitation {

	private String email;
	private String invitationUrl;

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getInvitationUrl() {
		return invitationUrl;
	}

	public void setInvitationUrl(String invitationUrl) {
		this.invitationUrl = invitationUrl;
	}
}
