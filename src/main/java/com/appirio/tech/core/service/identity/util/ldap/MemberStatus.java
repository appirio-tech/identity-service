package com.appirio.tech.core.service.identity.util.ldap;

import java.util.EnumSet;

public enum MemberStatus {
	/** registered but not verified */
	UNVERIFIED("U"),
	/** activated */
	ACTIVE("A"),
	/** user wanted account removed */
	INACTIVE_USER_REQUEST("4"),
	/** duplicate account */
	INACTIVE_DUPLICATE_ACCOUNT("5"),
	/** cheating/malicious behavior */
	INACTIVE_IRREGULAR_ACCOUNT("6"),
	/** unknown */
	UNKNOWN("");
	
	protected String value;
	MemberStatus(String value) {
		this.value = value;
	}
	public String getValue() {
		return this.value;
	}
	public static MemberStatus getByValue(String value) {
		if(value==null)
			return null;
		for (MemberStatus status : EnumSet.allOf(MemberStatus.class)) {
			if(value.equals(status.value))
				return status;
		}
		return null;
	}
}
