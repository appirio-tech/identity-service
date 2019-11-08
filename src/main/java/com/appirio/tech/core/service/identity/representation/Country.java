package com.appirio.tech.core.service.identity.representation;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Country {

	private String code;
	
	private String name;
	
	private String isoAlpha2Code;
	
	private String isoAlpha3Code;

	public Country(){}
	
	public Country(String code, String name) {
		this.code = code;
		this.name = name;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getISOAlpha2Code() {
		return isoAlpha2Code;
	}

	@JsonProperty("isoAlpha2Code")
	public void setISOAlpha2Code(String isoAlpha2Code) {
		this.isoAlpha2Code = isoAlpha2Code;
	}

	public String getISOAlpha3Code() {
		return isoAlpha3Code;
	}

	@JsonProperty("isoAlpha3Code")
	public void setISOAlpha3Code(String isoAlpha3Code) {
		this.isoAlpha3Code = isoAlpha3Code;
	}
}
