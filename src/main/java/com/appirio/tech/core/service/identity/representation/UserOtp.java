package com.appirio.tech.core.service.identity.representation;

import org.joda.time.DateTime;

import com.appirio.tech.core.service.identity.util.ldap.MemberStatus;

public class UserOtp {

	private Long id;
	private Long userId;
	private String handle;
	private String email;
	private String status;
	private String otp;
	private DateTime expireAt;
	private String resendToken;
	private Boolean resend;
	private int failCount;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Long getUserId() {
		return userId;
	}

	public void setUserId(Long userId) {
		this.userId = userId;
	}

	public String getHandle() {
		return handle;
	}

	public void setHandle(String handle) {
		this.handle = handle;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getStatus() {
		return this.status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getOtp() {
		return otp;
	}

	public void setOtp(String otp) {
		this.otp = otp;
	}

	public DateTime getExpireAt() {
		return expireAt;
	}

	public void setExpireAt(DateTime expireAt) {
		this.expireAt = expireAt;
	}

	public String getResendToken() {
		return resendToken;
	}

	public void setResendToken(String resendToken) {
		this.resendToken = resendToken;
	}

	public Boolean getResend() {
		return resend;
	}

	public void setResend(Boolean resend) {
		this.resend = resend;
	}

	public int getFailCount() {
		return failCount;
	}

	public void setFailCount(int failCount) {
		this.failCount = failCount;
	}

	public Boolean isActive() {
		return MemberStatus.ACTIVE.getValue().equals(this.status);
	}
}
