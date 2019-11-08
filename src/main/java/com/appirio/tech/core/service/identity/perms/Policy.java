package com.appirio.tech.core.service.identity.perms;

import java.util.HashMap;
import java.util.Map;

public class Policy {

	private String version = "1";
	private Map<String, PermissionRules> permissions;

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}
	
	public Policy withVersion(String version) {
		this.version = version;
		return this;
	}

	public Map<String, PermissionRules> getPermissions() {
		return permissions;
	}

	public void setPermissions(Map<String, PermissionRules> permissions) {
		this.permissions = permissions;
	}
	
	public Policy withPermissions(Map<String, PermissionRules> permissions) {
		this.permissions = permissions;
		return this;
	}
	
	public Policy putPermission(String action, PermissionRules rules) {
		if (permissions == null) {
			permissions = new HashMap<>();
		}
		permissions.put(action, rules);
		return this;
	}

}
 