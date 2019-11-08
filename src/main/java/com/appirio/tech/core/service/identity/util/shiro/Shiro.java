package com.appirio.tech.core.service.identity.util.shiro;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Shiro {
	
	@Valid
	@NotNull
	@JsonProperty
	boolean useShiroAuthorization;
	
	@Valid
	@NotNull
	@JsonProperty
	String iniConfigPath;
	
	public Shiro() {}
	
	public boolean isUseShiroAuthorization() {
		return useShiroAuthorization;
	}
	public void setUseShiroAuthorization(boolean useShiroAuthorization) {
		this.useShiroAuthorization = useShiroAuthorization;
	}
	public String getIniConfigPath() {
		return iniConfigPath;
	}
	public void setIniConfigPath(String iniConfigPath) {
		this.iniConfigPath = iniConfigPath;
	}

}
