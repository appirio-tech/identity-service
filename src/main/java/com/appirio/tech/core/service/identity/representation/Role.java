package com.appirio.tech.core.service.identity.representation;

import java.util.Set;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.model.AbstractIdResource;
import com.appirio.tech.core.api.v3.model.annotation.ApiMapping;


public class Role extends AbstractIdResource {

	private String roleName;
	private Set<TCID> subjects;

	public String getRoleName() {
		return roleName;
	}
	
	public void setRoleName(String roleName) {
		this.roleName = roleName;
	}
	
	@ApiMapping(queryDefault=false)
	public Set<TCID> getSubjects() {
		return subjects;
	}
	
	public void setSubjects(Set<TCID> subjects) {
		this.subjects = subjects;
	}
}
