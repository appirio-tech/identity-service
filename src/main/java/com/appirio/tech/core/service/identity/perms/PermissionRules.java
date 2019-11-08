package com.appirio.tech.core.service.identity.perms;

import java.util.ArrayList;
import java.util.List;

public class PermissionRules {

	private List<PermissionRule> allowRules;
	private List<PermissionRule> denyRules;
	
	public PermissionRules() {
		
	}
	
	public PermissionRules(List<PermissionRule> allowRules, List<PermissionRule> denyRules) {
		this.allowRules = allowRules;
		this.denyRules = denyRules;
	}

	public List<PermissionRule> getAllowRules() {
		return allowRules;
	}

	public void setAllowRules(List<PermissionRule> allowRules) {
		this.allowRules = allowRules;
	}

	public List<PermissionRule> getDenyRules() {
		return denyRules;
	}

	public void setDenyRules(List<PermissionRule> denyRules) {
		this.denyRules = denyRules;
	}
	
	public PermissionRules addAllowRule(PermissionRule rule) {
		if (allowRules == null) {
			allowRules = new ArrayList<>();
		}
		allowRules.add(rule);
		return this;
	}
	
	
}
