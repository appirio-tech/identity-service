package com.appirio.tech.core.service.identity.perms;

import java.util.Objects;

public class PolicySubject {

	private final String subjectId;
	private final String subjectType;
	
	public PolicySubject(String subjectId, String subjectType) {
		this.subjectId = subjectId;
		this.subjectType = subjectType;
	}

	public String getSubjectId() {
		return subjectId;
	}

	public String getSubjectType() {
		return subjectType;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj == null || (!getClass().equals(obj.getClass()))) {
			return false;
		}
		
		final PolicySubject other = (PolicySubject)obj;
		return Objects.equals(subjectId, other.subjectId) && Objects.equals(subjectType, other.subjectType); 
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(subjectId, subjectType);
	}
}
