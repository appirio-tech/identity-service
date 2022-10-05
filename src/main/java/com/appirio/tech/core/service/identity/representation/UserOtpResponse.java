package com.appirio.tech.core.service.identity.representation;

public class UserOtpResponse {

	private Boolean verified;
	private String resendToken;
	private Boolean blocked;
	private Boolean expired;

	public Boolean getVerified() {
		return verified;
	}

	public void setVerified(Boolean verified) {
		this.verified = verified;
	}

	public String getResendToken() {
		return resendToken;
	}

	public void setResendToken(String resendToken) {
		this.resendToken = resendToken;
	}

	public Boolean getBlocked() {
		return blocked;
	}

	public void setBlocked(Boolean blocked) {
		this.blocked = blocked;
	}

	public Boolean getExpired() {
		return expired;
	}

	public void setExpired(Boolean expired) {
		this.expired = expired;
	}

}
