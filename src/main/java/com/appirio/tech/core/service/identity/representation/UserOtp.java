package com.appirio.tech.core.service.identity.representation;

public class UserOtp {

	private Long userId;
	private String otp;

	public Long getUserId() {
		return userId;
	}

	public void setUserId(Long userId) {
		this.userId = userId;
	}

	public String getOtp() {
		return otp;
	}

	public void setOtp(String otp) {
		this.otp = otp;
	}
}
