package com.appirio.tech.core.service.identity.representation;

import com.fasterxml.jackson.annotation.JsonProperty;

public class DiceCallbackRequest {
	private String type;
	private String action;
	private String name;
	private String email;
    @JsonProperty(value = "connection_id")
	private String connectionId;
	@JsonProperty(value = "credential_exchange_id")
	private String credentialExchangeId;
    @JsonProperty(value = "presentation_exchange_id")
	private String presentationExchangeId;
    @JsonProperty(value = "schema_id")
	private String schemaId;
	
    public String getConnectionId() {
		return connectionId;
	}

	public void setConnectionId(String connectionId) {
		this.connectionId = connectionId;
	}

	public String getCredentialExchangeId() {
		return credentialExchangeId;
	}

	public void setCredentialExchangeId(String credentialExchangeId) {
		this.credentialExchangeId = credentialExchangeId;
	}

	public String getPresentationExchangeId() {
		return presentationExchangeId;
	}

	public void setPresentationExchangeId(String presentationExchangeId) {
		this.presentationExchangeId = presentationExchangeId;
	}

	public String getSchemaId() {
		return schemaId;
	}

	public void setSchemaId(String schemaId) {
		this.schemaId = schemaId;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getAction() {
		return action;
	}

	public void setAction(String action) {
		this.action = action;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}
}
