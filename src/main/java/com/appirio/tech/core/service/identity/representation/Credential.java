package com.appirio.tech.core.service.identity.representation;

import com.appirio.tech.core.service.identity.util.Utils;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Credential {

	/**
	 * The password field for the newly input password. This is transient field.
	 */
	private String password;
	
	/** 
	 * The password for old password validation when updating password. This is transient field.
	 */
	private String currentPassword;

	/**
	 * The encoded password. Password is stored as its encoded value.
	 */
	private String encodedPassword;
	
	private String activationCode;
	
	private String resetToken;

	@JsonIgnore
	public String getEncodedPassword() {
		return encodedPassword;
	}

	public void setEncodedPassword(String encodedPassword) {
		this.encodedPassword = encodedPassword;
	}

	@JsonIgnore
	public String getPassword() {
		return password;
	}

	@JsonProperty("password")
	public void setPassword(String password) {
		this.password = password;
		setEncodedPassword(encodePassword(this.password));
	}
	
	@JsonIgnore
	public String getCurrentPassword() {
		return currentPassword;
	}
	
	@JsonProperty("currentPassword")
	public void setCurrentPassword(String currentPassword) {
		this.currentPassword = currentPassword;
	}
	
	/**
	 * hasPassword tells whether an user's password in set in TopCoder/ASP or not.
	 * The case this tells false is that a user is registered with an external account (i.e. Facebook, Github). 
	 */
	@JsonProperty("hasPassword")
	public boolean hasPassword() {
		return isDefaultPassword(this.encodedPassword) == false;
	}

	public String getActivationCode() {
		return activationCode;
	}

	public void setActivationCode(String activationCode) {
		this.activationCode = activationCode;
	}
	
	public String getResetToken() {
		return resetToken;
	}

	public void setResetToken(String resetToken) {
		this.resetToken = resetToken;
	}

	public void clearResetToken() { this.resetToken = null; }

	public void clearActivationCode() { this.activationCode = null; }

	public boolean isCurrentPassword(String password) {
		if(this.encodedPassword==null && password==null)
			return true;
		if(this.encodedPassword==null || password==null)
			return false;
		return this.encodedPassword.trim().equals(encodePassword(password).trim());
	}
	
	protected String encodePassword(String password) {
		if(password==null)
			return null;
		return Utils.encodePassword(password);
	}
	
	protected boolean isDefaultPassword(String encPassword) {
		if(encPassword==null)
			return false;
		String defaultPassword = Utils.getEncodedDefaultPassword();
		return encPassword.equals(defaultPassword);
	}
}
