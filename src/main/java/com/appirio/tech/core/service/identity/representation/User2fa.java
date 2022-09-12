package com.appirio.tech.core.service.identity.representation;

import org.joda.time.DateTime;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class User2fa {

	private Long id;
	private long userId;
	@JsonIgnore
	private String handle;
	@JsonIgnore
	private String email;
	private Boolean mfaEnabled;
	private Boolean diceEnabled;
	private Long createdBy;
	private DateTime createdAt;
	private Long modifiedBy;
	private DateTime modifiedAt;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public long getUserId() {
		return userId;
	}

	public void setUserId(long userId) {
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

	public Boolean getMfaEnabled() {
		return mfaEnabled;
	}

	public void setMfaEnabled(Boolean mfaEnabled) {
		this.mfaEnabled = mfaEnabled;
	}

	public Boolean getDiceEnabled() {
		return diceEnabled;
	}

	public void setDiceEnabled(Boolean diceEnabled) {
		this.diceEnabled = diceEnabled;
	}

	public Long getCreatedBy() {
		return createdBy;
	}

	public void setCreatedBy(Long createdBy) {
		this.createdBy = createdBy;
	}

	public DateTime getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(DateTime createdAt) {
		this.createdAt = createdAt;
	}

	public Long getModifiedBy() {
		return modifiedBy;
	}

	public void setModifiedBy(Long modifiedBy) {
		this.modifiedBy = modifiedBy;
	}

	public DateTime getModifiedAt() {
		return modifiedAt;
	}

	public void setModifiedAt(DateTime modifiedAt) {
		this.modifiedAt = modifiedAt;
	}

}
