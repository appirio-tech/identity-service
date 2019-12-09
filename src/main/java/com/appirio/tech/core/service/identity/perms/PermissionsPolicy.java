package com.appirio.tech.core.service.identity.perms;

import com.appirio.tech.core.api.v3.model.annotation.ApiMapping;

import com.appirio.tech.core.api.v3.model.AbstractIdResource;

/**
 * 
 */
public class PermissionsPolicy extends AbstractIdResource {

	private String resource;
	private Policy policy;
	private String subjectId;
	private String subjectType;
	private String policyJson;

	public PermissionsPolicy() {
		
	}
	
	public PermissionsPolicy(String resource) {
		this.resource = resource;
	}
	
	public PermissionsPolicy(String subjectId, String subjectType, String resource, Policy policy) {
		this.subjectId = subjectId;
		this.subjectType = subjectType;
		this.resource = resource;
		this.policy = policy;
	}

	public String getResource() {
		return resource;
	}

	public void setResource(String resource) {
		this.resource = resource;
	}

	public Policy getPolicy() {
		return policy;
	}

	public void setPolicy(Policy policy) {
		this.policy = policy;
	}

	public String getSubjectId() {
		return subjectId;
	}

	public void setSubjectId(String subjectId) {
		this.subjectId = subjectId;
	}

	public String getSubjectType() {
		return subjectType;
	}

	public void setSubjectType(String subjectType) {
		this.subjectType = subjectType;
	}

	// Need this as currently tcmapper not able to serialize nested structure
	@ApiMapping(queryDefault=false)
	public String getPolicyJson() {
		return policyJson;
	}

	public void setPolicyJson(String policyJson) {
		this.policyJson = policyJson;
	}
}
