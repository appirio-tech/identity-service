package com.appirio.tech.core.service.identity.representation;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.model.AbstractIdResource;

public class Email extends AbstractIdResource {

	private TCID userId;
	
	private int typeId;
	
	private String address;
	
	private int statusId;

	public TCID getUserId() {
		return userId;
	}

	public void setUserId(TCID userId) {
		this.userId = userId;
	}

	public int getTypeId() {
		return typeId;
	}

	public void setTypeId(int typeId) {
		this.typeId = typeId;
	}

	public String getType() {
		return EmailType.getById(this.typeId).label;
	}

	public void setType(String type) {
		this.typeId = EmailType.getByLabel(type).id;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public int getStatusId() {
		return statusId;
	}

	public void setStatusId(int statusId) {
		this.statusId = statusId;
	}
}
