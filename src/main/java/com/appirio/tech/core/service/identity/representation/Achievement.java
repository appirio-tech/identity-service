package com.appirio.tech.core.service.identity.representation;

import org.joda.time.DateTime;

import com.appirio.tech.core.api.v3.model.AbstractIdResource;

public class Achievement extends AbstractIdResource {

	private int typeId;
	
	private String type;
	
	private String description;
	
	private DateTime achievementDate;
	
	public int getTypeId() {
		return typeId;
	}

	public void setTypeId(int typeId) {
		this.typeId = typeId;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public DateTime getAchievementDate() {
		return achievementDate;
	}

	public void setAchievementDate(DateTime achievementDate) {
		this.achievementDate = achievementDate;
	}
}
