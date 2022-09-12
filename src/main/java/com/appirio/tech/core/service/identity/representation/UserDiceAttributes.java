package com.appirio.tech.core.service.identity.representation;

import org.joda.time.DateTime;

public class UserDiceAttributes {

	private Long id;
	private long userId;
	private String handle;
	private String firstName;
	private String email;
	private Boolean mfaEnabled;
	private Boolean diceEnabled;
	private Long diceConnectionId;
	private String diceConnection;
	private Boolean diceConnectionAccepted;
	private DateTime diceConnectionCreatedAt;

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

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
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

	public Long getDiceConnectionId() {
		return diceConnectionId;
	}

	public void setDiceConnectionId(Long diceConnectionId) {
		this.diceConnectionId = diceConnectionId;
	}

	public String getDiceConnection() {
		return diceConnection;
	}

	public void setDiceConnection(String diceConnection) {
		this.diceConnection = diceConnection;
	}

	public Boolean getDiceConnectionAccepted() {
		return diceConnectionAccepted;
	}

	public void setDiceConnectionAccepted(Boolean diceConnectionAccepted) {
		this.diceConnectionAccepted = diceConnectionAccepted;
	}

	public DateTime getDiceConnectionCreatedAt() {
		return diceConnectionCreatedAt;
	}

	public void setDiceConnectionCreatedAt(DateTime diceConnectionCreatedAt) {
		this.diceConnectionCreatedAt = diceConnectionCreatedAt;
	}
}
