package com.appirio.tech.core.service.identity.representation;

public class DiceConnection {

	private String connection;
	private Boolean accepted;
	private Boolean diceEnabled;

	public String getConnection() {
		return connection;
	}

	public void setConnection(String connection) {
		this.connection = connection;
	}

	public Boolean getAccepted() {
		return accepted;
	}

	public void setAccepted(Boolean accepted) {
		this.accepted = accepted;
	}

	public Boolean getDiceEnabled() {
		return diceEnabled;
	}

	public void setDiceEnabled(Boolean diceEnabled) {
		this.diceEnabled = diceEnabled;
	}
}
